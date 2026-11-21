//! Resolves a write destination without reopening checked path components.
//!
//! Each directory is held open while looking up its children. The final
//! directory handle also anchors the temporary file and rename, so a path
//! change during a prompt cannot redirect the write.

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

/// The directory handle and basename identify the destination for all I/O.
/// The path is retained for diagnostics, where it may be stale if the directory
/// has been moved since resolution.
pub(super) struct OutputDestination {
    pub(super) directory: File,
    pub(super) name: OsString,
    pub(super) path: PathBuf,
}

impl OutputDestination {
    /// Walks the output route component by component, applying the ownership
    /// rule to links in both the directory path and the final name.
    pub(super) fn resolve(path: &Path) -> Result<Self> {
        let mut pending = components(path);
        let mut resolved_dir = PathBuf::from(if path.is_absolute() { "/" } else { "." });
        let mut directory = open_search_dir(at::CWD, &resolved_dir)
            .map_err(|err| directory_error(&resolved_dir, path, err))?;
        let mut leaf_target = None;
        let mut followed = 0;
        while let Some(name) = pending.pop_front() {
            let candidate = resolved_dir.join(&name);
            let entry = entry_stat(&directory, &name).map_err(|err| {
                path_error(format!("failed to inspect output path {candidate:?} while preparing to write {path:?}"), err)
            })?;
            if let Some(entry) = entry {
                if FileType::from_raw_mode(entry.st_mode) == FileType::Symlink {
                    // A bound also catches cycles through parent components.
                    if followed == 40 {
                        return Err(user_error(format!(
                            "too many symbolic links in output path {path:?}"
                        )));
                    }
                    followed += 1;
                    let target = checked_link_target(&directory, &name, &candidate)?;
                    if pending.is_empty() && leaf_target.is_none() {
                        leaf_target = Some(target.clone());
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
            } else if let Some(target) = &leaf_target {
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

    /// Rechecks the exact directory entry before naming the temporary file.
    /// For update the validated file is still open, which prevents inode reuse.
    pub(super) fn verify_for_save(&self, existing: Option<&File>) -> Result<()> {
        let entry = entry_stat(&self.directory, &self.name).map_err(|err| {
            path_error(
                format!("failed to inspect output path {:?}", self.path),
                err,
            )
        })?;
        if let Some(existing) = existing {
            let expected = at::fstat(existing).map_err(|err| {
                path_error(
                    format!("failed to inspect the encrypted file {:?}", self.path),
                    err.into(),
                )
            })?;
            if !entry.is_some_and(|actual| {
                actual.st_dev == expected.st_dev && actual.st_ino == expected.st_ino
            }) {
                return Err(user_error(format!(
                    "output file {:?} changed while preparing the update",
                    self.path
                )));
            }
        }
        check_output_type(&self.path, entry.as_ref())
    }

    /// Reuses the tempfile builder's name generation while creating the file
    /// relative to the held directory. Cleanup must use that handle too.
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

    pub(super) fn rename_tempfile(&self, path: &Path) -> io::Result<()> {
        Ok(at::renameat(
            &self.directory,
            temp_name(path),
            &self.directory,
            &self.name,
        )?)
    }

    pub(super) fn remove_tempfile(&self, path: &Path) -> io::Result<()> {
        Ok(at::unlinkat(
            &self.directory,
            temp_name(path),
            AtFlags::empty(),
        )?)
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
        if !trust_link(
            parent.st_mode,
            parent.st_uid,
            entry.st_uid,
            rustix::process::geteuid().as_raw(),
        ) {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "symbolic link in a public sticky directory belongs to another user",
            ));
        }
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

/// Public sticky directories allow other accounts to create names. Trust
/// links owned by the current account or the owner who manages those names.
fn trust_link(
    mode: rustix::fs::RawMode,
    directory_uid: u32,
    link_uid: u32,
    current_uid: u32,
) -> bool {
    let public_sticky = Mode::SVTX | Mode::WOTH;
    !Mode::from_bits_truncate(mode).contains(public_sticky)
        || link_uid == directory_uid
        || link_uid == current_uid
}

/// Linux accepts an empty pathname to inspect the open symbolic link itself.
#[cfg(target_os = "linux")]
fn read_link_handle(link: &OwnedFd) -> io::Result<PathBuf> {
    let target = at::readlinkat(link, "", Vec::new())?;
    Ok(OsStr::from_bytes(target.as_bytes()).into())
}

/// macOS 13 provides the descriptor-based equivalent of readlinkat.
#[cfg(target_os = "macos")]
#[allow(unsafe_code)]
fn read_link_handle(link: &OwnedFd) -> io::Result<PathBuf> {
    use std::os::fd::AsRawFd;

    let mut target = [0u8; libc::PATH_MAX as usize + 1];
    // SAFETY: link remains open and target is writable for its full length.
    let count =
        unsafe { libc::freadlink(link.as_raw_fd(), target.as_mut_ptr().cast(), target.len()) };
    if count < 0 {
        return Err(io::Error::last_os_error());
    }
    if count as usize == target.len() {
        return Err(io::Error::from_raw_os_error(libc::ENAMETOOLONG));
    }
    Ok(OsStr::from_bytes(&target[..count as usize]).into())
}

/// Preserve the distinct error for a missing output directory.
fn directory_error(directory: &Path, path: &Path, err: io::Error) -> SaltyboxError {
    let message = if err.kind() == io::ErrorKind::NotFound {
        format!("output directory {directory:?} does not exist")
    } else {
        format!("failed to open output directory {directory:?} while preparing to write {path:?}")
    };
    path_error(message, err)
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
        assert!(trust_link(shared, 1, 1, 2));
        assert!(trust_link(shared, 1, 2, 2));
        assert!(!trust_link(shared, 1, 3, 2));
        assert!(trust_link(Mode::WOTH.as_raw_mode(), 1, 3, 2));
        assert!(trust_link(Mode::SVTX.as_raw_mode(), 1, 3, 2));
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
        std::fs::remove_file(&path).unwrap();
        std::os::unix::fs::symlink("second", &path).unwrap();

        assert_eq!(read_link_handle(&link).unwrap(), Path::new("first"));
    }
}
