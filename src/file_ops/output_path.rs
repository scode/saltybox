//! Resolves a write destination without reopening checked path components.
//!
//! Each directory is held open while looking up its children. The final
//! directory handle also anchors the temporary file and rename, so a path
//! change during a prompt cannot redirect the write.

use super::directory_error;
use crate::error::{ErrorCategory, ErrorKind, Result, SaltyboxError};
use rustix::fs::{self as at, AtFlags, FileType, Mode, OFlags, Stat};
use rustix::io::Errno;
use std::collections::VecDeque;
use std::ffi::{OsStr, OsString};
use std::fs::File;
use std::io;
use std::os::fd::{AsFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};

// Bound resolution across both directory and final-name links.
const MAX_SYMLINK_HOPS: usize = 40;

/// The directory handle and basename identify the destination for all I/O.
/// The path is retained for diagnostics, where it may be stale if the directory
/// has been moved since resolution.
pub(super) struct OutputDestination {
    directory: File,
    name: OsString,
    // A link supplied as the final name must keep referring to an existing
    // file. A link in a directory component can lead to a new filename.
    requires_existing_target: bool,
    pub(super) path: PathBuf,
}

impl OutputDestination {
    /// Walks the output route component by component, applying the ownership
    /// rule to links in both the directory path and the final name.
    ///
    /// A missing final filename is valid unless the user supplied a link to
    /// it. An existing entry must be regular. The returned path describes the
    /// resolved route and the parent is readable so it can be synced.
    pub(super) fn resolve(path: &Path) -> Result<Self> {
        let mut pending = components(path);
        let mut resolved_dir = PathBuf::from(if path.is_absolute() { "/" } else { "." });
        let mut directory = open_search_dir(at::CWD, &resolved_dir)
            .map_err(|err| directory_error(&resolved_dir, path, err))?;
        // Keep the first target for the dangling-link diagnostic.
        let mut leaf_link_target = None;
        let mut followed = 0;
        while let Some(name) = pending.pop_front() {
            let candidate = resolved_dir.join(&name);
            let entry = entry_stat(&directory, &name).map_err(|err| {
                let message = format!(
                    "failed to inspect output path {candidate:?} while preparing to write {path:?}"
                );
                path_error(message, err)
            })?;
            if let Some(entry) = entry {
                if FileType::from_raw_mode(entry.st_mode) == FileType::Symlink {
                    // A bound also catches cycles through parent components.
                    if followed == MAX_SYMLINK_HOPS {
                        return Err(user_error(format!(
                            "too many symbolic links in output path {path:?}"
                        )));
                    }
                    followed += 1;
                    let target = checked_link_target(&directory, &name, &candidate)?;
                    if pending.is_empty() && leaf_link_target.is_none() {
                        leaf_link_target = Some(target.clone());
                    }
                    if target.is_absolute() {
                        resolved_dir = PathBuf::from("/");
                        directory = open_search_dir(at::CWD, &resolved_dir)
                            .map_err(|err| directory_error(&resolved_dir, path, err))?;
                    }
                    let mut target_components = components(&target);
                    target_components.append(&mut pending);
                    pending = target_components;
                    continue;
                }
            } else if let Some(target) = &leaf_link_target {
                return Err(user_error(format!(
                    "output path {path:?} is a symlink to {target:?}, which does not exist"
                )));
            }

            if pending.is_empty() {
                check_output_type(&candidate, entry.as_ref())?;
                // Traversal only needs search permission. The final directory
                // must be opened for reading so it can be synced after rename.
                let directory = at::openat(
                    &directory,
                    ".",
                    OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
                    Mode::empty(),
                )
                .map_err(|err| directory_error(&resolved_dir, path, err.into()))?;
                return Ok(Self {
                    directory: File::from(directory),
                    name,
                    requires_existing_target: leaf_link_target.is_some(),
                    path: candidate,
                });
            }
            directory = open_search_dir(&directory, Path::new(&name))
                .map_err(|err| directory_error(&candidate, path, err))?;
            resolved_dir = candidate;
        }
        Err(user_error(format!(
            "output path {path:?} names a directory"
        )))
    }

    /// Opens the resolved encrypted file. No-follow prevents a replacement
    /// link from redirecting the read, and nonblocking avoids waiting if a
    /// different process puts a pipe at the name before it is opened.
    pub(super) fn open_existing(&self) -> io::Result<File> {
        let file = at::openat(
            &self.directory,
            &self.name,
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
            Mode::empty(),
        )?;
        if FileType::from_raw_mode(at::fstat(&file)?.st_mode) != FileType::RegularFile {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "output must be a regular file",
            ));
        }
        Ok(File::from(file))
    }

    /// Rechecks the exact directory entry before creating a tempfile and
    /// again before renaming it. Encrypt and decrypt allow a missing name
    /// unless the final argument component was a symlink. Update requires
    /// the open file that was validated.
    pub(super) fn verify_for_save(&self, existing: Option<&File>) -> Result<()> {
        let expected = existing.map(at::fstat).transpose().map_err(|err| {
            path_error(
                format!("failed to inspect the encrypted file {:?}", self.path),
                err.into(),
            )
        })?;
        let entry = entry_stat(&self.directory, &self.name).map_err(|err| {
            path_error(
                format!("failed to inspect output path {:?}", self.path),
                err,
            )
        })?;
        if let Some(expected) = expected {
            let unchanged = entry.is_some_and(|actual| {
                actual.st_dev == expected.st_dev && actual.st_ino == expected.st_ino
            });
            if !unchanged {
                return Err(user_error(format!(
                    "output file {:?} changed while preparing the update",
                    self.path
                )));
            }
        } else if self.requires_existing_target && entry.is_none() {
            return Err(user_error(format!(
                "output symlink target {:?} no longer exists",
                self.path
            )));
        }
        check_output_type(&self.path, entry.as_ref())
    }

    /// Reuses the tempfile builder's name generation while creating the file
    /// relative to the held directory. Mode 0600 protects plaintext from
    /// creation onward. Drop leaves the file alone because the recorded path
    /// may be stale. Callers must publish it or clean it up through this
    /// directory handle.
    pub(super) fn create_tempfile(&self) -> io::Result<tempfile::NamedTempFile> {
        super::tempfile_builder().disable_cleanup(true).make_in(
            self.path.parent().expect("resolved path has a parent"),
            |candidate| {
                let file = at::openat(
                    &self.directory,
                    temp_name(candidate),
                    OFlags::RDWR | OFlags::CREATE | OFlags::EXCL | OFlags::CLOEXEC,
                    Mode::RUSR | Mode::WUSR,
                )?;
                Ok(File::from(file))
            },
        )
    }

    /// Returns the tempfile on failure so the caller can report cleanup errors.
    pub(super) fn persist_tempfile(
        &self,
        file: tempfile::NamedTempFile,
    ) -> std::result::Result<(), tempfile::PersistError> {
        if let Err(error) = at::renameat(
            &self.directory,
            temp_name(file.path()),
            &self.directory,
            &self.name,
        ) {
            return Err(tempfile::PersistError {
                error: error.into(),
                file,
            });
        }
        Ok(())
    }

    /// Makes the rename durable in the directory that received the new name.
    pub(super) fn sync_directory(&self) -> io::Result<()> {
        self.directory.sync_all()
    }

    pub(super) fn remove_tempfile(&self, path: &Path) -> io::Result<()> {
        Ok(at::unlinkat(
            &self.directory,
            temp_name(path),
            AtFlags::empty(),
        )?)
    }

    /// The recorded path can be stale even if the temp file was just created.
    /// Ask for the directory's current path only when the user needs it.
    pub(super) fn tempfile_location(&self, path: &Path) -> String {
        #[cfg(target_os = "linux")]
        let directory = {
            use std::os::fd::AsRawFd;
            std::fs::read_link(format!("/proc/self/fd/{}", self.directory.as_raw_fd()))
        };
        #[cfg(target_os = "macos")]
        let directory = at::getpath(&self.directory)
            .map(|path| PathBuf::from(OsStr::from_bytes(path.as_bytes())));
        match directory {
            Ok(directory) => format!("{:?}", directory.join(temp_name(path))),
            Err(_) => format!(
                "{:?} (original path {path:?}, directory may have moved)",
                temp_name(path)
            ),
        }
    }
}

/// The builder records a path for diagnostics. Only its generated basename
/// belongs in syscalls relative to the held directory.
fn temp_name(path: &Path) -> &OsStr {
    path.file_name().expect("temporary file has a name")
}

/// Retains a directory requirement on link targets ending in a slash.
/// Without it, a symlink to `file/` could resolve to the regular file.
fn components(path: &Path) -> VecDeque<OsString> {
    let bytes = path.as_os_str().as_bytes();
    let mut parts: VecDeque<_> = bytes
        .split(|&byte| byte == b'/')
        .filter(|part| !part.is_empty())
        .map(|part| OsStr::from_bytes(part).to_os_string())
        .collect();
    if bytes.ends_with(b"/") {
        parts.push_back(OsString::from("."));
    }
    parts
}

/// Opens the named directory itself. A link swapped in after inspection fails
/// here instead of silently bypassing the ownership check.
fn open_search_dir(directory: impl AsFd, name: &Path) -> io::Result<OwnedFd> {
    #[cfg(target_os = "linux")]
    let access = OFlags::PATH;
    #[cfg(target_os = "macos")]
    let access = OFlags::from_bits_retain(libc::O_SEARCH as _);
    Ok(at::openat(
        directory,
        name,
        access | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )?)
}

/// A missing entry is a valid destination for encrypt and decrypt.
/// Everything else, including a replacement symlink, is examined as-is.
fn entry_stat(directory: impl AsFd, name: &OsStr) -> io::Result<Option<Stat>> {
    match at::statat(directory, name, AtFlags::SYMLINK_NOFOLLOW) {
        Ok(entry) => Ok(Some(entry)),
        Err(Errno::NOENT) => Ok(None),
        Err(err) => Err(err.into()),
    }
}

/// A pipe or device must never become a regular file holding output data.
fn check_output_type(path: &Path, entry: Option<&Stat>) -> Result<()> {
    let Some(entry) = entry else {
        return Ok(());
    };
    match FileType::from_raw_mode(entry.st_mode) {
        FileType::RegularFile => Ok(()),
        FileType::Directory => Err(user_error(format!(
            "output path {path:?} names a directory"
        ))),
        _ => Err(user_error(format!(
            "output path {path:?} is not a regular file"
        ))),
    }
}

/// Checks ownership and reads target text through the same link descriptor.
/// Looking up its name again would let a replacement supply different text
/// after the ownership decision.
fn checked_link_target(directory: &OwnedFd, name: &OsStr, path: &Path) -> Result<PathBuf> {
    let get_target = || -> io::Result<PathBuf> {
        let link = open_link(directory, name)?;
        let entry = at::fstat(&link)?;
        if FileType::from_raw_mode(entry.st_mode) != FileType::Symlink {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "entry changed while resolving the output path",
            ));
        }
        let parent = at::fstat(directory)?;
        check_link_owner(
            parent.st_mode,
            parent.st_uid,
            entry.st_uid,
            rustix::process::geteuid().as_raw(),
            #[cfg(target_os = "linux")]
            linux_overflow_uid,
        )?;
        read_link_handle(&link)
    };
    get_target()
        .map_err(|err| path_error(format!("failed to resolve output symlink {path:?}"), err))
}

/// Opens the link itself. The descriptor carries the ownership and target.
fn open_link(directory: &OwnedFd, name: &OsStr) -> rustix::io::Result<OwnedFd> {
    #[cfg(target_os = "linux")]
    let flags = OFlags::PATH | OFlags::NOFOLLOW;
    #[cfg(target_os = "macos")]
    let flags = OFlags::SYMLINK | OFlags::NONBLOCK;
    at::openat(directory, name, flags | OFlags::CLOEXEC, Mode::empty())
}

/// A public sticky directory requires the link to belong to the running
/// account or the directory owner. On Linux, an overflow UID can represent
/// multiple different owners and cannot establish either match.
fn check_link_owner(
    mode: rustix::fs::RawMode,
    directory_uid: u32,
    link_uid: u32,
    current_uid: u32,
    #[cfg(target_os = "linux")] overflow_uid: impl FnOnce() -> io::Result<u32>,
) -> io::Result<()> {
    let public_sticky = Mode::SVTX | Mode::WOTH;
    if !Mode::from_bits_truncate(mode).contains(public_sticky) {
        return Ok(());
    }
    if link_uid != directory_uid && link_uid != current_uid {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "symbolic link in a public sticky directory belongs to another user",
        ));
    }
    #[cfg(target_os = "linux")]
    if link_uid == overflow_uid()? {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "cannot verify link ownership in a public sticky directory: the owner is reported as the Linux overflow UID",
        ));
    }
    Ok(())
}

/// Reads the kernel's configured fallback UID. Without it we cannot tell
/// whether a matching UID came from a successful mapping.
#[cfg(target_os = "linux")]
fn linux_overflow_uid() -> io::Result<u32> {
    let value = std::fs::read_to_string("/proc/sys/kernel/overflowuid").map_err(|err| {
        io::Error::new(
            err.kind(),
            format!("cannot read the Linux overflow UID: {err}"),
        )
    })?;
    value.trim().parse().map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "the Linux overflow UID is not a valid UID",
        )
    })
}

/// Reads text only from links that can be resolved as ordinary paths.
/// Inspect the mount of the held link so the policy applies to the same
/// object that supplies the target, wherever the filesystem is mounted.
#[cfg(target_os = "linux")]
fn read_link_handle(link: &OwnedFd) -> io::Result<PathBuf> {
    check_linux_link_mount(&at::fstatfs(link)?)?;
    let target = at::readlinkat(link, "", Vec::new())?;
    link_target_path(target.as_bytes())
}

/// Refuses links whose text cannot be expanded under the mount's rules.
/// Procfs can encode kernel references and `nosymfollow` allows reading a
/// link's text without granting permission to traverse it.
#[cfg(target_os = "linux")]
fn check_linux_link_mount(mount: &at::StatFs) -> io::Result<()> {
    if mount.f_type == at::PROC_SUPER_MAGIC {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "output paths cannot follow symbolic links on procfs",
        ));
    }
    // Linux defines ST_NOSYMFOLLOW as 0x2000 in <linux/statfs.h>.
    if mount.f_flags & 0x2000 != 0 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "output paths cannot follow symbolic links on a nosymfollow mount",
        ));
    }
    Ok(())
}

/// macOS 13 provides the descriptor-based equivalent of readlinkat.
#[cfg(target_os = "macos")]
#[allow(unsafe_code)]
fn read_link_handle(link: &OwnedFd) -> io::Result<PathBuf> {
    use std::os::fd::AsRawFd;

    // The pinned libc binding has a narrower return type than Apple's header.
    unsafe extern "C" {
        fn freadlink(fd: libc::c_int, buf: *mut libc::c_char, size: libc::size_t) -> libc::ssize_t;
    }

    let mut target = [0u8; libc::PATH_MAX as usize + 1];
    // SAFETY: link remains open and target is writable for its full length.
    let count = unsafe { freadlink(link.as_raw_fd(), target.as_mut_ptr().cast(), target.len()) };
    if count < 0 {
        return Err(io::Error::last_os_error());
    }
    if count as usize == target.len() {
        return Err(io::Error::from_raw_os_error(libc::ENAMETOOLONG));
    }
    link_target_path(&target[..count as usize])
}

/// Rejects an empty target before the path walk can skip the link entirely.
/// Some filesystems, including HFS+, can store a link with zero target bytes.
fn link_target_path(target: &[u8]) -> io::Result<PathBuf> {
    if target.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            "symbolic link target is empty",
        ));
    }
    Ok(OsStr::from_bytes(target).into())
}

fn path_error(message: String, err: io::Error) -> SaltyboxError {
    SaltyboxError::with_kind_and_source(ErrorCategory::User, ErrorKind::Io, message, err)
}

fn user_error(message: String) -> SaltyboxError {
    SaltyboxError::with_kind(ErrorCategory::User, ErrorKind::Io, message)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Exercises all three ownership outcomes without needing multiple Unix accounts.
    #[test]
    fn public_sticky_directory_requires_a_trusted_link_owner() {
        let shared = (Mode::SVTX | Mode::WOTH).as_raw_mode();
        let check = |mode, link_uid| {
            check_link_owner(
                mode,
                1,
                link_uid,
                2,
                #[cfg(target_os = "linux")]
                || Ok(65534),
            )
        };
        assert!(check(shared, 1).is_ok());
        assert!(check(shared, 2).is_ok());
        assert!(check(shared, 3).is_err());
        assert!(check(Mode::WOTH.as_raw_mode(), 3).is_ok());
        assert!(check(Mode::SVTX.as_raw_mode(), 3).is_ok());
    }

    /// The configured fallback UID carries no ownership evidence, even when
    /// it equals the directory owner or the running account's reported UID.
    #[cfg(target_os = "linux")]
    #[test]
    fn overflow_uid_cannot_establish_link_ownership() {
        let shared = (Mode::SVTX | Mode::WOTH).as_raw_mode();
        let overflow_uid = 60000;
        for (directory_uid, current_uid) in [(overflow_uid, 2), (1, overflow_uid)] {
            let err = check_link_owner(shared, directory_uid, overflow_uid, current_uid, || {
                Ok(overflow_uid)
            })
            .unwrap_err();
            assert_eq!(err.kind(), io::ErrorKind::PermissionDenied);
        }
        assert!(check_link_owner(shared, 65534, 65534, 2, || Ok(overflow_uid)).is_ok());
    }

    /// Missing kernel settings make owner matches unsafe in a public sticky
    /// directory. Ordinary directory traversal does not need this setting.
    #[cfg(target_os = "linux")]
    #[test]
    fn unavailable_overflow_uid_rejects_only_links_that_need_ownership_checks() {
        let unavailable = || Err(io::Error::from(io::ErrorKind::NotFound));
        let shared = (Mode::SVTX | Mode::WOTH).as_raw_mode();
        let err = check_link_owner(shared, 1, 1, 2, unavailable).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::NotFound);
        assert!(check_link_owner(Mode::WOTH.as_raw_mode(), 1, 1, 2, unavailable).is_ok());
    }

    /// The read must stay attached to the link whose ownership was inspected.
    /// Test the native descriptor read after the name no longer refers to it.
    #[test]
    fn opened_link_retains_its_target_after_replacement() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("link");
        std::os::unix::fs::symlink("first", &path).unwrap();
        let parent = open_search_dir(at::CWD, temp.path()).unwrap();
        let link = open_link(&parent, OsStr::new("link")).unwrap();
        // Keep the inspected link alive by name. macOS can reject freadlink
        // on a vnode that was unlinked after it was opened.
        std::fs::rename(&path, temp.path().join("old-link")).unwrap();
        std::os::unix::fs::symlink("second", &path).unwrap();

        assert_eq!(read_link_handle(&link).unwrap(), Path::new("first"));
    }

    /// A descriptor read can succeed with no target bytes. Treat that as a
    /// dangling link even on test filesystems that cannot store one.
    #[test]
    fn an_empty_link_target_is_dangling() {
        let err = link_target_path(b"").unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::NotFound);
        assert_eq!(err.to_string(), "symbolic link target is empty");
    }

    /// Exercise the mount decision without requiring mount privileges. An
    /// unrelated filesystem flag must leave ordinary link traversal allowed.
    #[cfg(target_os = "linux")]
    #[test]
    fn nosymfollow_mounts_reject_output_links() {
        let file = tempfile::tempfile().unwrap();
        let mut mount = at::fstatfs(&file).unwrap();
        mount.f_type = 0;
        mount.f_flags = 0x4; // ST_NODEV is unrelated to link traversal.
        check_linux_link_mount(&mount).unwrap();
        mount.f_flags |= 0x2000; // ST_NOSYMFOLLOW.
        let err = check_linux_link_mount(&mount).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::PermissionDenied);
        assert!(err.to_string().contains("nosymfollow"), "{err}");
    }

    /// Procfs links must fail before the resolver uses their displayed names,
    /// including when a procfs link is an intermediate directory component.
    #[cfg(target_os = "linux")]
    #[test]
    fn procfs_links_are_refused_in_output_routes() {
        let proc = Path::new("/proc");
        let Ok(directory) = open_search_dir(at::CWD, proc) else {
            return; // Some test environments run without procfs.
        };
        if at::fstatfs(&directory).unwrap().f_type != at::PROC_SUPER_MAGIC {
            return;
        }

        for path in [proc.join("self"), proc.join("self/saltybox-test-output")] {
            let err = OutputDestination::resolve(&path)
                .err()
                .expect("expected procfs link rejection");
            assert_eq!(err.category, ErrorCategory::User);
            let cause = std::error::Error::source(&err).unwrap();
            assert_eq!(
                cause.to_string(),
                "output paths cannot follow symbolic links on procfs"
            );
        }
    }

    /// A circular directory link must fail without creating an output file.
    #[test]
    fn directory_link_cycle_is_rejected() {
        let temp = tempfile::tempdir().unwrap();
        let link = temp.path().join("loop");
        std::os::unix::fs::symlink("loop", &link).unwrap();
        let err = OutputDestination::resolve(&link.join("output"))
            .err()
            .expect("expected cycle rejection");
        assert_eq!(err.category, ErrorCategory::User);
        assert!(err.to_string().contains("too many symbolic links"), "{err}");
        assert_eq!(std::fs::read_dir(temp.path()).unwrap().count(), 1);
    }
}
