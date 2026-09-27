//! File encryption/decryption operations
//!
//! This module provides high-level file operations for encrypting, decrypting,
//! and updating files using the saltybox format.

use crate::error::{ErrorCategory, ErrorKind, Result, SaltyboxError};
use crate::format;
use crate::passphrase::PassphraseReader;
use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use tempfile::NamedTempFile;
use zeroize::Zeroizing;

const TEMPFILE_PREFIX: &str = ".saltybox-";
const TEMPFILE_SUFFIX: &str = ".tmp";

/// Reads the passphrase and rejects one that is empty or contains a line
/// break.
///
/// Both are refused for all operations, because both are almost always an
/// accident when piping to `--passphrase-stdin` rather than intent. The
/// canonical cases are `echo -n "$PASS"` with `PASS` unset, which sends zero
/// bytes, and `echo "$PASS"` without `-n`, which appends a newline (and with
/// `PASS` unset sends nothing else). Either would otherwise silently produce
/// a file protected by nothing, or by a passphrase the user does not know
/// they chose. A line break is `\n` or `\r`, so Windows-style `\r\n` endings
/// are caught too. Line breaks are rejected anywhere, not just at the end:
/// piped input is meant to be a single-line passphrase, and feeding arbitrary
/// bytes is left to a possible future option that reads the passphrase from
/// a file.
///
/// The checks live here at the operation layer, not in the individual
/// [`PassphraseReader`] implementations, so they hold regardless of how the
/// passphrase was obtained.
fn read_valid_passphrase(reader: &mut dyn PassphraseReader) -> Result<Zeroizing<Vec<u8>>> {
    let passphrase = reader.read_passphrase()?;
    if passphrase.is_empty() {
        return Err(SaltyboxError::with_kind(
            ErrorCategory::User,
            ErrorKind::EmptyPassphrase,
            "empty passphrase is not allowed (note that an unset shell variable expands to empty)",
        ));
    }
    if passphrase.iter().any(|b| matches!(b, b'\n' | b'\r')) {
        return Err(SaltyboxError::with_kind(
            ErrorCategory::User,
            ErrorKind::PassphraseContainsLineBreak,
            "passphrase containing a line break is not allowed (when piping to --passphrase-stdin, use `echo -n` or `printf '%s' \"$PASS\"`)",
        ));
    }
    Ok(passphrase)
}

/// Encrypt a file with a passphrase
///
/// Reads plaintext from `input_path`, encrypts it using a passphrase from
/// `passphrase_reader`, and writes the armored ciphertext to `output_path`.
/// If the reader offers a confirmation (see
/// [`PassphraseReader::read_confirmation`]), a confirmation that differs from
/// the passphrase fails the call as a user error before anything is written.
///
/// Which format is written is the caller's choice via `write_engine`; the
/// CLI always passes [`format::default_write_engine`].
///
/// Output is written atomically via a same-directory temporary file. A
/// symlinked `output_path` is followed and the file it ultimately points to
/// is replaced; the temporary file goes in that file's directory.
/// On Unix systems, the final file mode is set to 0o600 (read/write for owner only).
pub fn encrypt_file(
    input_path: &Path,
    output_path: &Path,
    passphrase_reader: &mut dyn PassphraseReader,
    write_engine: &dyn format::FormatEngine,
) -> Result<()> {
    check_output_path(output_path)?;
    let plaintext = Zeroizing::new(fs::read(input_path).map_err(|e| read_error(input_path, e))?);
    let passphrase = read_valid_passphrase(passphrase_reader)?;
    // A new file has nothing to check the passphrase against, so an
    // interactive entry is confirmed by typing it twice. See
    // `PassphraseReader::read_confirmation` for which sources confirm.
    if let Some(confirmation) = passphrase_reader.read_confirmation()? {
        if confirmation != passphrase {
            return Err(SaltyboxError::with_kind(
                ErrorCategory::User,
                ErrorKind::PassphraseConfirmationMismatch,
                "passphrase entries do not match; nothing was written",
            ));
        }
    }
    let armored = write_engine
        .encrypt(&passphrase, &plaintext)
        .map_err(|e| e.with_context("encryption failed"))?;
    write_file_secure(output_path, armored.as_bytes())
        .map_err(|e| e.with_context(format!("failed to write to {}", output_path.display())))
}

/// Decrypt a file with a passphrase
///
/// Reads armored ciphertext from `input_path`, decrypts it using a passphrase from
/// `passphrase_reader`, and writes the plaintext to `output_path`.
///
/// Output is written atomically via a same-directory temporary file. A
/// symlinked `output_path` is followed and the file it ultimately points to
/// is replaced; the temporary file goes in that file's directory.
/// On Unix systems, the final file mode is set to 0o600 (read/write for owner only).
pub fn decrypt_file(
    input_path: &Path,
    output_path: &Path,
    passphrase_reader: &mut dyn PassphraseReader,
) -> Result<()> {
    check_output_path(output_path)?;
    let armored_bytes = fs::read(input_path).map_err(|e| read_error(input_path, e))?;
    let armored = String::from_utf8(armored_bytes).map_err(|e| {
        SaltyboxError::with_kind_and_source(
            ErrorCategory::User,
            ErrorKind::Io,
            "input file is not valid UTF-8",
            e,
        )
    })?;
    let passphrase = read_valid_passphrase(passphrase_reader)?;
    let (engine, ciphertext) =
        format::decode(&armored).map_err(|e| e.with_context("failed to unarmor"))?;
    let plaintext = engine
        .decrypt(&passphrase, &ciphertext)
        .map_err(|e| e.with_context("failed to decrypt"))?;
    write_file_secure(output_path, &plaintext)
        .map_err(|e| e.with_context(format!("failed to write to {}", output_path.display())))
}

/// Update an encrypted file with new plaintext using the same passphrase
///
/// This function:
/// 1. Decrypts the existing file at `crypt_path` to validate the passphrase
/// 2. Reads new plaintext from `plain_path`
/// 3. Encrypts the new plaintext with the validated passphrase
/// 4. Atomically writes to `crypt_path` (tempfile + fsync + rename); a
///    symlinked `crypt_path` is followed, so the file validated in step 1 is
///    the file replaced here
///
/// The atomic write ensures that either the old file or the new file exists,
/// never a partial/corrupted file.
///
/// The passphrase validation prevents accidental passphrase changes.
///
/// The output format follows `write_engine` alone, never the existing file's
/// format: updating with a different engine than the file was written with
/// silently converts it (this is the intended migration path).
pub fn update_file(
    plain_path: &Path,
    crypt_path: &Path,
    passphrase_reader: &mut dyn PassphraseReader,
    write_engine: &dyn format::FormatEngine,
) -> Result<()> {
    check_output_path(crypt_path)?;
    // Prevent treating the existing ciphertext as new plaintext when paths alias.
    if update_paths_conflict(plain_path, crypt_path) {
        return Err(SaltyboxError::with_kind(
            ErrorCategory::User,
            ErrorKind::Io,
            "input and output paths must be different for update",
        ));
    }

    let armored_bytes = fs::read(crypt_path).map_err(|e| read_error(crypt_path, e))?;
    let armored = String::from_utf8(armored_bytes).map_err(|e| {
        SaltyboxError::with_kind_and_source(
            ErrorCategory::User,
            ErrorKind::Io,
            "encrypted file is not valid UTF-8",
            e,
        )
    })?;
    let passphrase = read_valid_passphrase(passphrase_reader)?;

    // Validate passphrase by decrypting existing file (discard plaintext)
    let (engine, ciphertext) =
        format::decode(&armored).map_err(|e| e.with_context("failed to unarmor"))?;
    engine
        .decrypt(&passphrase, &ciphertext)
        .map_err(|e| e.with_context("failed to decrypt"))?;

    let new_plaintext =
        Zeroizing::new(fs::read(plain_path).map_err(|e| read_error(plain_path, e))?);
    let new_armored = write_engine
        .encrypt(&passphrase, &new_plaintext)
        .map_err(|e| e.with_context("failed to encrypt"))?;
    write_file_secure(crypt_path, new_armored.as_bytes())
        .map_err(|e| e.with_context(format!("failed to write to {}", crypt_path.display())))
}

/// Detects whether the update input and output refer to the same file.
///
/// Three alias classes are covered: identical paths, paths that canonicalize
/// to the same target (symlinks, `..` traversal), and on Unix, distinct
/// directory entries hardlinked to the same inode — which canonicalize to
/// different paths and would slip past the first two checks.
///
/// This is a best-effort guard against the user clobbering their ciphertext,
/// not a security boundary: it races against concurrent filesystem changes.
fn update_paths_conflict(plain_path: &Path, crypt_path: &Path) -> bool {
    plain_path == crypt_path
        || matches!(
            (fs::canonicalize(plain_path), fs::canonicalize(crypt_path)),
            (Ok(canonical_plain), Ok(canonical_crypt)) if canonical_plain == canonical_crypt
        )
        || paths_are_same_inode(plain_path, crypt_path)
}

#[cfg(unix)]
fn paths_are_same_inode(plain_path: &Path, crypt_path: &Path) -> bool {
    use std::os::unix::fs::MetadataExt;

    matches!(
        (fs::metadata(plain_path), fs::metadata(crypt_path)),
        (Ok(plain_meta), Ok(crypt_meta))
            if plain_meta.dev() == crypt_meta.dev() && plain_meta.ino() == crypt_meta.ino()
    )
}

#[cfg(not(unix))]
fn paths_are_same_inode(_plain_path: &Path, _crypt_path: &Path) -> bool {
    false
}

/// Rejects output paths that cannot name a file, before any I/O touches them.
///
/// Both cases are almost always a shell variable that expanded to empty, and
/// both get a message that says so rather than whatever the first filesystem
/// call would report. All three commands run this first, before reading
/// input or prompting for a passphrase: it only looks at the argument, so a
/// bad `-o` should fail before the user types a passphrase and waits out key
/// derivation (and, for `update`, before the read of the existing file would
/// fail with a generic read error). `write_file_secure` runs it again as a
/// guard for any future caller.
fn check_output_path(path: &Path) -> Result<()> {
    // An empty path is almost always an unset shell variable, the same
    // mistake the empty-passphrase check guards against. It is caught here
    // by name rather than falling through to the parent lookup in `write_file_secure`, whose
    // "no parent directory" wording describes the mechanism, not the mistake.
    if path.as_os_str().is_empty() {
        return Err(SaltyboxError::with_kind(
            ErrorCategory::User,
            ErrorKind::Io,
            "empty output path is not allowed (note that an unset shell variable expands to empty)",
        ));
    }
    // A path ending in a separator can only name a directory. It has to be
    // caught before the parent lookup in `write_file_secure`, because `Path` ignores trailing
    // separators: `nodir/` would yield parent "" (so "."), the directory
    // check would pass on the working directory, and a tempfile holding the
    // output would be created there before the rename finally failed. Like an
    // empty path, it is usually an unset shell variable (`-o "$DIR/$NAME"`).
    // Checking the last encoded byte is sound because every separator is ASCII,
    // and bytes of multi-byte characters in UTF-8 and WTF-8 are always >= 0x80.
    if path
        .as_os_str()
        .as_encoded_bytes()
        .last()
        .is_some_and(|&b| std::path::is_separator(char::from(b)))
    {
        return Err(SaltyboxError::with_kind(
            ErrorCategory::User,
            ErrorKind::Io,
            format!(
                "output path {} ends in a path separator, so it names a directory rather than a file (an unset shell variable at the end of the path, as in \"$DIR/$NAME\", produces this)",
                path.display()
            ),
        ));
    }
    Ok(())
}

/// Replaces a file through a private same-directory temporary file.
///
/// A symlinked `path` is followed to the file it ultimately points to, and
/// that file is replaced; see [`resolve_output_symlink`].
///
/// Successful writes sync the tempfile contents on every platform; on Unix
/// they additionally sync the containing directory so the replacement
/// survives crashes that happen after rename returns. On Unix the resulting
/// file mode is `0600`. Any failure after the tempfile is created removes it;
/// if removal fails, the returned error names the tempfile.
fn write_file_secure(path: &Path, contents: &[u8]) -> Result<()> {
    check_output_path(path)?;
    // Everything below writes next to, and renames onto, the file a symlinked
    // output path ultimately points to rather than the link itself.
    let resolved = resolve_output_symlink(path)?;
    let path = resolved.as_deref().unwrap_or(path);
    // The empty path and trailing separators (including the root `/`) are
    // rejected by `check_output_path`, so on Unix only a path such as `/.`,
    // whose final component `Path` normalizes away, reaches this branch; it
    // keeps the mechanical description.
    let output_dir = path.parent().ok_or_else(|| {
        SaltyboxError::with_kind(
            ErrorCategory::User,
            ErrorKind::Io,
            "output path has no parent directory",
        )
    })?;
    let output_dir = if output_dir.as_os_str().is_empty() {
        Path::new(".")
    } else {
        output_dir
    };
    #[cfg(unix)]
    let output_dir_file = fs::File::open(output_dir).map_err(|e| {
        // This open happens before anything is written, so neither message may
        // imply a write occurred. A missing directory is additionally a user
        // mistake (typoed output path) and gets a message saying so.
        let msg = if e.kind() == io::ErrorKind::NotFound {
            format!("output directory {} does not exist", output_dir.display())
        } else {
            format!(
                "failed to open output directory {} while preparing to write {}",
                output_dir.display(),
                path.display()
            )
        };
        // The output directory is the user's choice, so any failure opening
        // it (missing, unreadable, not a directory) is a user error.
        SaltyboxError::with_kind_and_source(ErrorCategory::User, ErrorKind::Io, msg, e)
    })?;
    let mut temp_file = create_tempfile(output_dir).map_err(|e| {
        // Creating the tempfile is the first operation that depends on
        // the output directory being writable, which is the user's
        // environment (permissions, a read-only mount, a full disk).
        SaltyboxError::with_kind_and_source(
            ErrorCategory::User,
            ErrorKind::Io,
            format!("failed to create tempfile for {}", path.display()),
            e,
        )
    })?;

    if let Err(e) = fill_tempfile(&mut temp_file, path, contents) {
        return Err(discard_tempfile(temp_file, e));
    }
    if let Err(tempfile::PersistError { error, file }) = temp_file.persist(path) {
        // The rename target is the output path the user gave with `-o`, or the
        // file it ultimately points to when it is a symlink; the realistic
        // failure (it names an existing directory) is the user's mistake, so
        // this is a user error per SPEC.md.
        let err = SaltyboxError::with_kind_and_source(
            ErrorCategory::User,
            ErrorKind::Io,
            format!("failed to rename to target file {}", path.display()),
            error,
        );
        return Err(discard_tempfile(file, err));
    }
    #[cfg(unix)]
    {
        // `fill_tempfile`'s sync covers the bytes. The directory sync makes the
        // rename itself durable so a crash cannot lose the new directory entry.
        output_dir_file.sync_all().map_err(|e| {
            SaltyboxError::with_kind_and_source(
                ErrorCategory::Internal,
                ErrorKind::Io,
                format!("failed to sync directory after writing {}", path.display()),
                e,
            )
        })?;
    }
    Ok(())
}

/// Resolves an output path that is a symbolic link to the file it ultimately
/// points to, following chains of links. Returns `None` when the path is not
/// a symlink, when nothing exists there yet, or when it cannot be inspected
/// at all, so the caller writes to the path as given; in the last case the
/// caller's directory open reports the failure with its own message.
///
/// Writing through the link keeps reads and writes consistent. The final
/// step of a write renames a tempfile onto the output path, and a rename
/// replaces the directory entry it lands on: aimed at the link, it would turn
/// the link into a regular file and leave the real file stale. For `update`,
/// which has just validated the passphrase by reading the existing file
/// through the link, that meant reporting success while the file it checked
/// was never updated.
///
/// A link whose target does not exist is refused rather than followed to
/// create the target, as SPEC.md requires. Hard links need no handling here;
/// renaming onto one name simply leaves the file's other names with the old
/// contents.
fn resolve_output_symlink(path: &Path) -> Result<Option<PathBuf>> {
    match fs::symlink_metadata(path) {
        Ok(meta) if meta.file_type().is_symlink() => match fs::canonicalize(path) {
            Ok(target) => Ok(Some(target)),
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                // Naming where the link points is what the user needs to fix
                // it; for a chain this is the first hop.
                let msg = match fs::read_link(path) {
                    Ok(target) => format!(
                        "output path {} is a symlink to {}, which does not exist",
                        path.display(),
                        target.display()
                    ),
                    Err(_) => format!(
                        "output path {} is a symlink to a nonexistent file",
                        path.display()
                    ),
                };
                Err(SaltyboxError::with_kind(
                    ErrorCategory::User,
                    ErrorKind::Io,
                    msg,
                ))
            }
            Err(e) => Err(SaltyboxError::with_kind_and_source(
                ErrorCategory::User,
                ErrorKind::Io,
                format!("failed to resolve output symlink {}", path.display()),
                e,
            )),
        },
        _ => Ok(None),
    }
}

/// Creates the private tempfile a write goes through, in `output_dir` so the
/// final rename stays within one filesystem and is atomic.
///
/// The name (`.saltybox-` prefix, `.tmp` suffix) and, on Unix, the
/// owner-only mode are part of SPEC.md's contract: a tempfile left behind by
/// a crash has to be recognizable, and must not expose plaintext to other
/// users while it exists.
fn create_tempfile(output_dir: &Path) -> io::Result<NamedTempFile> {
    tempfile::Builder::new()
        .prefix(TEMPFILE_PREFIX)
        .suffix(TEMPFILE_SUFFIX)
        .tempfile_in(output_dir)
}

/// Writes, flushes, syncs, and (on Unix) restricts the tempfile, so a rename
/// that follows always publishes complete, durable, owner-only contents.
fn fill_tempfile(temp_file: &mut NamedTempFile, path: &Path, contents: &[u8]) -> Result<()> {
    temp_file.write_all(contents).map_err(|e| {
        SaltyboxError::with_kind_and_source(
            ErrorCategory::Internal,
            ErrorKind::Io,
            format!("failed to write {}", path.display()),
            e,
        )
    })?;
    // Ensure persisted rename always points to fully written data.
    temp_file.flush().map_err(|e| {
        SaltyboxError::with_kind_and_source(
            ErrorCategory::Internal,
            ErrorKind::Io,
            format!("failed to flush {}", path.display()),
            e,
        )
    })?;
    temp_file.as_file().sync_all().map_err(|e| {
        SaltyboxError::with_kind_and_source(
            ErrorCategory::Internal,
            ErrorKind::Io,
            format!("failed to sync {}", path.display()),
            e,
        )
    })?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        temp_file
            .as_file()
            .set_permissions(fs::Permissions::from_mode(0o600))
            .map_err(|e| {
                SaltyboxError::with_kind_and_source(
                    ErrorCategory::Internal,
                    ErrorKind::Io,
                    "failed to set tempfile permissions",
                    e,
                )
            })?;
    }
    Ok(())
}

/// Removes the tempfile after a failure that happened once it existed, and
/// returns the failure's error, extended when the removal itself fails.
///
/// Every failure between creating the tempfile and a successful rename goes
/// through here. The removal is explicit instead of being left to
/// `NamedTempFile`'s destructor for two reasons. The destructor ignores a
/// failed removal, and for `decrypt` a leftover tempfile is a copy of the
/// plaintext, so the user has to be told where it is. And the destructor ties
/// removal to whoever ends up holding the handle, and does not run at all if
/// the process exits without unwinding.
///
/// The file is removed with `fs::remove_file` on the bare path rather than
/// `NamedTempFile::close`, whose error text repeats the path; the message
/// below names the path once and keeps the OS error's own wording, which is
/// more specific than its `io::ErrorKind`. A tempfile that is already gone
/// (`NotFound`) counts as removed.
fn discard_tempfile(temp_file: NamedTempFile, err: SaltyboxError) -> SaltyboxError {
    let (file, temp_path) = temp_file.into_parts();
    drop(file);
    let removal = fs::remove_file(&temp_path);
    // Disarm the `TempPath` destructor: removal was just attempted, and a
    // silent second attempt could only hide what the message below reports.
    let tempfile_path = match temp_path.keep() {
        Ok(path) => path,
        Err(e) => e.path.to_path_buf(),
    };
    match removal {
        Ok(()) => err,
        Err(cleanup_err) if cleanup_err.kind() == io::ErrorKind::NotFound => err,
        Err(cleanup_err) => err.with_context(format!(
            "failed to remove tempfile {} after the error below ({}); remove it by hand",
            tempfile_path.display(),
            cleanup_err
        )),
    }
}

/// Wraps a failed read of a user-supplied path as a user error.
///
/// Every I/O failure on a path the user named is classified as a user error,
/// not just a missing file: a directory passed as a file, a permission
/// denial, an unreadable mount are all the caller's environment. Internal is
/// reserved for failures on the tool's own tempfile writes and syncs, where
/// the path was chosen by this code. SPEC.md states the split.
fn read_error(path: &Path, err: io::Error) -> SaltyboxError {
    SaltyboxError::with_kind_and_source(
        ErrorCategory::User,
        ErrorKind::Io,
        format!("failed to read from {}", path.display()),
        err,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::{ErrorCategory, ErrorKind};
    use crate::format_v2::V2Engine;
    use crate::passphrase::{ConfirmingPassphraseReader, ConstantPassphraseReader};
    use std::fs;
    use tempfile::TempDir;

    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;

    /// Most tests here exercise file-handling behavior that does not depend
    /// on which format is written; these wrappers keep those call sites
    /// one-liners. Tests where the engine choice is the point pass engines
    /// to [`encrypt_file`]/[`update_file`] explicitly.
    fn encrypt_with_default_engine(
        input_path: &Path,
        output_path: &Path,
        passphrase_reader: &mut dyn PassphraseReader,
    ) -> Result<()> {
        encrypt_file(
            input_path,
            output_path,
            passphrase_reader,
            format::default_write_engine(),
        )
    }

    /// See [`encrypt_with_default_engine`].
    fn update_with_default_engine(
        plain_path: &Path,
        crypt_path: &Path,
        passphrase_reader: &mut dyn PassphraseReader,
    ) -> Result<()> {
        update_file(
            plain_path,
            crypt_path,
            passphrase_reader,
            format::default_write_engine(),
        )
    }

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let temp_dir = TempDir::new().unwrap();
        let plain_path = temp_dir.path().join("plain.txt");
        let crypt_path = temp_dir.path().join("crypt.txt.saltybox");
        let decrypted_path = temp_dir.path().join("decrypted.txt");

        let plaintext = b"Hello, saltybox!";
        fs::write(&plain_path, plaintext).unwrap();

        let mut reader = ConstantPassphraseReader::new(b"test password".to_vec());
        encrypt_with_default_engine(&plain_path, &crypt_path, &mut reader).unwrap();
        assert!(crypt_path.exists());

        let mut reader = ConstantPassphraseReader::new(b"test password".to_vec());
        decrypt_file(&crypt_path, &decrypted_path, &mut reader).unwrap();
        let decrypted = fs::read(&decrypted_path).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_encrypt_file_with_v2_engine_roundtrips() {
        let temp_dir = TempDir::new().unwrap();
        let plain_path = temp_dir.path().join("plain.txt");
        let crypt_path = temp_dir.path().join("crypt.txt.saltybox");
        let decrypted_path = temp_dir.path().join("decrypted.txt");

        fs::write(&plain_path, b"v2 write path").unwrap();

        let mut reader = ConstantPassphraseReader::new(b"pw".to_vec());
        encrypt_file(&plain_path, &crypt_path, &mut reader, &V2Engine).unwrap();
        assert!(
            fs::read_to_string(&crypt_path)
                .unwrap()
                .starts_with("saltybox2:")
        );

        let mut reader = ConstantPassphraseReader::new(b"pw".to_vec());
        decrypt_file(&crypt_path, &decrypted_path, &mut reader).unwrap();
        assert_eq!(fs::read(&decrypted_path).unwrap(), b"v2 write path");
    }

    /// The output format follows the write engine alone, never the input
    /// file's format: updating a saltybox1 file with the (v2) default engine
    /// upgrades it. This is the intended migration path for old files. The
    /// v1 file is constructed from the frozen v1 modules directly, since
    /// nothing exposes a v1 write engine anymore.
    #[test]
    fn test_update_upgrades_v1_file_to_default_format() {
        let temp_dir = TempDir::new().unwrap();
        let plain_path = temp_dir.path().join("plain.txt");
        let crypt_path = temp_dir.path().join("crypt.txt.saltybox");
        let decrypted_path = temp_dir.path().join("decrypted.txt");

        let v1_armored =
            crate::varmor::wrap(&crate::secretcrypt_v1::encrypt(b"pw", b"original").unwrap());
        fs::write(&crypt_path, &v1_armored).unwrap();

        fs::write(&plain_path, b"upgraded").unwrap();
        let mut reader = ConstantPassphraseReader::new(b"pw".to_vec());
        update_with_default_engine(&plain_path, &crypt_path, &mut reader).unwrap();
        assert!(
            fs::read_to_string(&crypt_path)
                .unwrap()
                .starts_with("saltybox2:")
        );

        let mut reader = ConstantPassphraseReader::new(b"pw".to_vec());
        decrypt_file(&crypt_path, &decrypted_path, &mut reader).unwrap();
        assert_eq!(fs::read(&decrypted_path).unwrap(), b"upgraded");
    }

    #[test]
    fn test_update_file() {
        let temp_dir = TempDir::new().unwrap();
        let plain1_path = temp_dir.path().join("plain1.txt");
        let plain2_path = temp_dir.path().join("plain2.txt");
        let crypt_path = temp_dir.path().join("crypt.txt.saltybox");

        let plaintext1 = b"Initial content";
        fs::write(&plain1_path, plaintext1).unwrap();

        let mut reader = ConstantPassphraseReader::new(b"test password".to_vec());
        encrypt_with_default_engine(&plain1_path, &crypt_path, &mut reader).unwrap();

        let plaintext2 = b"Updated content";
        fs::write(&plain2_path, plaintext2).unwrap();

        let mut reader = ConstantPassphraseReader::new(b"test password".to_vec());
        update_with_default_engine(&plain2_path, &crypt_path, &mut reader).unwrap();

        let decrypted_path = temp_dir.path().join("decrypted.txt");
        let mut reader = ConstantPassphraseReader::new(b"test password".to_vec());
        decrypt_file(&crypt_path, &decrypted_path, &mut reader).unwrap();

        let decrypted = fs::read(&decrypted_path).unwrap();
        assert_eq!(decrypted, plaintext2);
    }

    #[test]
    fn test_update_rejects_identical_input_output_path() {
        let temp_dir = TempDir::new().unwrap();
        let plain_path = temp_dir.path().join("plain.txt");
        let crypt_path = temp_dir.path().join("crypt.txt.saltybox");

        let original = b"Initial content";
        fs::write(&plain_path, original).unwrap();

        let mut reader = ConstantPassphraseReader::new(b"test password".to_vec());
        encrypt_with_default_engine(&plain_path, &crypt_path, &mut reader).unwrap();

        let mut reader = ConstantPassphraseReader::new(b"test password".to_vec());
        let result = update_with_default_engine(&crypt_path, &crypt_path, &mut reader);

        let err = result.expect_err("expected path conflict failure");
        assert_eq!(err.category, ErrorCategory::User);
        assert_eq!(err.kind, Some(ErrorKind::Io));
        assert_eq!(
            err.message(),
            "input and output paths must be different for update"
        );

        let decrypted_path = temp_dir.path().join("decrypted.txt");
        let mut reader = ConstantPassphraseReader::new(b"test password".to_vec());
        decrypt_file(&crypt_path, &decrypted_path, &mut reader).unwrap();
        let decrypted = fs::read(&decrypted_path).unwrap();
        assert_eq!(decrypted, original);
    }

    #[test]
    fn test_update_rejects_canonical_alias_of_output_path() {
        let temp_dir = TempDir::new().unwrap();
        let plain_path = temp_dir.path().join("plain.txt");
        let crypt_path = temp_dir.path().join("crypt.txt.saltybox");
        let alias_dir = temp_dir.path().join("alias");
        let alias_path = alias_dir.join("..").join("crypt.txt.saltybox");

        let original = b"Initial content";
        fs::write(&plain_path, original).unwrap();

        let mut reader = ConstantPassphraseReader::new(b"test password".to_vec());
        encrypt_with_default_engine(&plain_path, &crypt_path, &mut reader).unwrap();

        fs::create_dir(&alias_dir).unwrap();

        let mut reader = ConstantPassphraseReader::new(b"test password".to_vec());
        let result = update_with_default_engine(&alias_path, &crypt_path, &mut reader);

        let err = result.expect_err("expected canonical path conflict failure");
        assert_eq!(err.category, ErrorCategory::User);
        assert_eq!(err.kind, Some(ErrorKind::Io));
        assert_eq!(
            err.message(),
            "input and output paths must be different for update"
        );

        let decrypted_path = temp_dir.path().join("decrypted.txt");
        let mut reader = ConstantPassphraseReader::new(b"test password".to_vec());
        decrypt_file(&crypt_path, &decrypted_path, &mut reader).unwrap();
        let decrypted = fs::read(&decrypted_path).unwrap();
        assert_eq!(decrypted, original);
    }

    /// A symlink to the ciphertext, passed as the new-plaintext input, must be
    /// rejected and the ciphertext left intact.
    ///
    /// Symlinks are the alias class SPEC.md names explicitly, yet the
    /// `..`-traversal test is the only one exercising the canonicalization
    /// path. Two independent checks catch a symlink today: canonicalization
    /// and, on Unix, the inode comparison, since `fs::metadata` follows
    /// links. This test exists so that weakening both (say, replacing
    /// canonicalization with textual normalization and dropping the inode
    /// check as redundant) fails loudly instead of letting an update clobber
    /// the file it was meant to read. Unix-only because creating symlinks
    /// portably needs platform-specific APIs and Windows is unsupported.
    #[test]
    #[cfg(unix)]
    fn test_update_rejects_symlink_alias_of_output_path() {
        let temp_dir = TempDir::new().unwrap();
        let plain_path = temp_dir.path().join("plain.txt");
        let crypt_path = temp_dir.path().join("crypt.txt.saltybox");
        let symlink_path = temp_dir.path().join("crypt-symlink.saltybox");

        let original = b"Initial content";
        fs::write(&plain_path, original).unwrap();

        let mut reader = ConstantPassphraseReader::new(b"test password".to_vec());
        encrypt_with_default_engine(&plain_path, &crypt_path, &mut reader).unwrap();

        std::os::unix::fs::symlink(&crypt_path, &symlink_path).unwrap();

        let mut reader = ConstantPassphraseReader::new(b"test password".to_vec());
        let result = update_with_default_engine(&symlink_path, &crypt_path, &mut reader);

        let err = result.expect_err("expected symlink path conflict failure");
        assert_eq!(err.category, ErrorCategory::User);
        assert_eq!(err.kind, Some(ErrorKind::Io));
        assert_eq!(
            err.message(),
            "input and output paths must be different for update"
        );

        let decrypted_path = temp_dir.path().join("decrypted.txt");
        let mut reader = ConstantPassphraseReader::new(b"test password".to_vec());
        decrypt_file(&crypt_path, &decrypted_path, &mut reader).unwrap();
        let decrypted = fs::read(&decrypted_path).unwrap();
        assert_eq!(decrypted, original);
    }

    /// `update` through a symlinked output path replaces the file the link
    /// points to and leaves the link in place.
    ///
    /// The passphrase check reads the existing file through the link, so the
    /// write has to land on the same file: renaming onto the link itself used
    /// to replace the link with a regular file and leave the real file (the
    /// one that was validated) holding the old ciphertext, while reporting
    /// success. SPEC.md now requires reads and writes to agree.
    #[test]
    #[cfg(unix)]
    fn test_update_through_symlink_replaces_target_and_keeps_link() {
        let temp_dir = TempDir::new().unwrap();
        let vault_dir = temp_dir.path().join("vault");
        fs::create_dir(&vault_dir).unwrap();
        let real_path = vault_dir.join("secret.salty");
        let link_path = temp_dir.path().join("link.salty");
        let plain_path = temp_dir.path().join("plain.txt");

        fs::write(&plain_path, b"old").unwrap();
        let mut reader = ConstantPassphraseReader::new(b"pw".to_vec());
        encrypt_with_default_engine(&plain_path, &real_path, &mut reader).unwrap();
        std::os::unix::fs::symlink(&real_path, &link_path).unwrap();

        fs::write(&plain_path, b"new").unwrap();
        let mut reader = ConstantPassphraseReader::new(b"pw".to_vec());
        update_with_default_engine(&plain_path, &link_path, &mut reader).unwrap();

        assert!(
            fs::symlink_metadata(&link_path)
                .unwrap()
                .file_type()
                .is_symlink(),
            "the link must survive the update"
        );
        let decrypted_path = temp_dir.path().join("decrypted.txt");
        let mut reader = ConstantPassphraseReader::new(b"pw".to_vec());
        decrypt_file(&real_path, &decrypted_path, &mut reader).unwrap();
        assert_eq!(fs::read(&decrypted_path).unwrap(), b"new");
        // Nothing was left behind in the target's directory.
        let mut vault_entries: Vec<_> = fs::read_dir(&vault_dir)
            .unwrap()
            .map(|entry| entry.unwrap().file_name().into_string().unwrap())
            .collect();
        vault_entries.sort();
        assert_eq!(vault_entries, ["secret.salty"]);
    }

    /// A chain of symlinks is followed to the final file, which the output
    /// replaces, and every link in the chain survives. This is the
    /// "ultimate target" half of the SPEC.md rule: resolving only one level
    /// would still overwrite a link.
    #[test]
    #[cfg(unix)]
    fn test_encrypt_through_symlink_chain_replaces_final_target() {
        let temp_dir = TempDir::new().unwrap();
        let plain_path = temp_dir.path().join("plain.txt");
        let target_path = temp_dir.path().join("target.salty");
        let inner_link = temp_dir.path().join("inner.salty");
        let outer_link = temp_dir.path().join("outer.salty");

        fs::write(&plain_path, b"payload").unwrap();
        fs::write(&target_path, b"placeholder").unwrap();
        std::os::unix::fs::symlink(&target_path, &inner_link).unwrap();
        std::os::unix::fs::symlink(&inner_link, &outer_link).unwrap();

        let mut reader = ConstantPassphraseReader::new(b"pw".to_vec());
        encrypt_with_default_engine(&plain_path, &outer_link, &mut reader).unwrap();

        for link in [&inner_link, &outer_link] {
            assert!(
                fs::symlink_metadata(link).unwrap().file_type().is_symlink(),
                "{} must still be a symlink",
                link.display()
            );
        }
        let decrypted_path = temp_dir.path().join("decrypted.txt");
        let mut reader = ConstantPassphraseReader::new(b"pw".to_vec());
        decrypt_file(&target_path, &decrypted_path, &mut reader).unwrap();
        assert_eq!(fs::read(&decrypted_path).unwrap(), b"payload");
    }

    /// An output symlink whose target does not exist is refused as a user
    /// error naming where the link points, and neither the target nor
    /// anything else is created. SPEC.md requires refusing rather than
    /// following the link to create its target.
    #[test]
    #[cfg(unix)]
    fn test_output_symlink_to_nonexistent_file_is_rejected() {
        let temp_dir = TempDir::new().unwrap();
        let plain_path = temp_dir.path().join("plain.txt");
        let missing_target = temp_dir.path().join("missing.salty");
        let link_path = temp_dir.path().join("dangling.salty");

        fs::write(&plain_path, b"payload").unwrap();
        std::os::unix::fs::symlink(&missing_target, &link_path).unwrap();

        let mut reader = ConstantPassphraseReader::new(b"pw".to_vec());
        let err = encrypt_with_default_engine(&plain_path, &link_path, &mut reader)
            .expect_err("expected dangling output symlink to be refused");

        assert_eq!(err.category, ErrorCategory::User);
        assert_eq!(err.kind, Some(ErrorKind::Io));
        let mut chain = String::new();
        let mut source: Option<&(dyn std::error::Error + 'static)> = Some(&err);
        while let Some(e) = source {
            chain.push_str(&e.to_string());
            chain.push('\n');
            source = e.source();
        }
        assert!(
            chain.contains(&format!(
                "is a symlink to {}, which does not exist",
                missing_target.display()
            )),
            "chain: {chain}"
        );
        let mut entries: Vec<_> = fs::read_dir(temp_dir.path())
            .unwrap()
            .map(|entry| entry.unwrap().file_name().into_string().unwrap())
            .collect();
        entries.sort();
        assert_eq!(entries, ["dangling.salty", "plain.txt"]);
    }

    #[test]
    #[cfg(unix)]
    fn test_update_rejects_hardlink_alias_of_output_path() {
        let temp_dir = TempDir::new().unwrap();
        let plain_path = temp_dir.path().join("plain.txt");
        let crypt_path = temp_dir.path().join("crypt.txt.saltybox");
        let hardlink_path = temp_dir.path().join("crypt-hardlink.saltybox");

        let original = b"Initial content";
        fs::write(&plain_path, original).unwrap();

        let mut reader = ConstantPassphraseReader::new(b"test password".to_vec());
        encrypt_with_default_engine(&plain_path, &crypt_path, &mut reader).unwrap();

        // A hardlink canonicalizes to its own path, so only the inode check
        // can catch this alias.
        fs::hard_link(&crypt_path, &hardlink_path).unwrap();

        let mut reader = ConstantPassphraseReader::new(b"test password".to_vec());
        let result = update_with_default_engine(&hardlink_path, &crypt_path, &mut reader);

        let err = result.expect_err("expected hardlink path conflict failure");
        assert_eq!(err.category, ErrorCategory::User);
        assert_eq!(err.kind, Some(ErrorKind::Io));
        assert_eq!(
            err.message(),
            "input and output paths must be different for update"
        );

        let decrypted_path = temp_dir.path().join("decrypted.txt");
        let mut reader = ConstantPassphraseReader::new(b"test password".to_vec());
        decrypt_file(&crypt_path, &decrypted_path, &mut reader).unwrap();
        let decrypted = fs::read(&decrypted_path).unwrap();
        assert_eq!(decrypted, original);
    }

    #[test]
    fn test_update_with_wrong_passphrase_fails() {
        let temp_dir = TempDir::new().unwrap();
        let plain1_path = temp_dir.path().join("plain1.txt");
        let plain2_path = temp_dir.path().join("plain2.txt");
        let crypt_path = temp_dir.path().join("crypt.txt.saltybox");

        fs::write(&plain1_path, b"Initial").unwrap();
        let mut reader = ConstantPassphraseReader::new(b"correct password".to_vec());
        encrypt_with_default_engine(&plain1_path, &crypt_path, &mut reader).unwrap();

        fs::write(&plain2_path, b"Updated").unwrap();
        let mut reader = ConstantPassphraseReader::new(b"wrong password".to_vec());
        let result = update_with_default_engine(&plain2_path, &crypt_path, &mut reader);

        let err = result.expect_err("expected authentication failure");
        assert_eq!(err.kind, Some(ErrorKind::AuthenticationFailed));

        let decrypted_path = temp_dir.path().join("decrypted.txt");
        let mut reader = ConstantPassphraseReader::new(b"correct password".to_vec());
        decrypt_file(&crypt_path, &decrypted_path, &mut reader).unwrap();
        let decrypted = fs::read(&decrypted_path).unwrap();
        assert_eq!(decrypted, b"Initial");
    }

    #[test]
    #[cfg(unix)]
    fn test_file_permissions() {
        let temp_dir = TempDir::new().unwrap();
        let plain_path = temp_dir.path().join("plain.txt");
        let crypt_path = temp_dir.path().join("crypt.txt.saltybox");

        fs::write(&plain_path, b"test").unwrap();

        let mut reader = ConstantPassphraseReader::new(b"test".to_vec());
        encrypt_with_default_engine(&plain_path, &crypt_path, &mut reader).unwrap();

        let metadata = fs::metadata(&crypt_path).unwrap();
        let permissions = metadata.permissions();
        assert_eq!(permissions.mode() & 0o777, 0o600);
    }

    #[test]
    #[cfg(unix)]
    fn test_encrypt_overwrites_insecure_output_permissions() {
        let temp_dir = TempDir::new().unwrap();
        let plain_path = temp_dir.path().join("plain.txt");
        let crypt_path = temp_dir.path().join("crypt.txt.saltybox");

        fs::write(&plain_path, b"secret").unwrap();
        fs::write(&crypt_path, b"existing ciphertext").unwrap();
        let mut permissions = fs::metadata(&crypt_path).unwrap().permissions();
        permissions.set_mode(0o644);
        fs::set_permissions(&crypt_path, permissions).unwrap();

        let mut reader = ConstantPassphraseReader::new(b"test".to_vec());
        encrypt_with_default_engine(&plain_path, &crypt_path, &mut reader).unwrap();

        let metadata = fs::metadata(&crypt_path).unwrap();
        let permissions = metadata.permissions();
        assert_eq!(permissions.mode() & 0o777, 0o600);
    }

    #[test]
    #[cfg(unix)]
    fn test_decrypt_overwrites_insecure_output_permissions() {
        let temp_dir = TempDir::new().unwrap();
        let plain_path = temp_dir.path().join("plain.txt");
        let crypt_path = temp_dir.path().join("crypt.txt.saltybox");
        let decrypted_path = temp_dir.path().join("decrypted.txt");

        fs::write(&plain_path, b"secret").unwrap();

        let mut reader = ConstantPassphraseReader::new(b"test".to_vec());
        encrypt_with_default_engine(&plain_path, &crypt_path, &mut reader).unwrap();

        fs::write(&decrypted_path, b"old plaintext").unwrap();
        let mut permissions = fs::metadata(&decrypted_path).unwrap().permissions();
        permissions.set_mode(0o644);
        fs::set_permissions(&decrypted_path, permissions).unwrap();

        let mut reader = ConstantPassphraseReader::new(b"test".to_vec());
        decrypt_file(&crypt_path, &decrypted_path, &mut reader).unwrap();

        let metadata = fs::metadata(&decrypted_path).unwrap();
        let permissions = metadata.permissions();
        assert_eq!(permissions.mode() & 0o777, 0o600);
    }

    #[test]
    #[cfg(unix)]
    fn test_decrypt_write_failure_preserves_existing_output() {
        let temp_dir = TempDir::new().unwrap();
        let output_dir = temp_dir.path().join("output");
        let plain_path = temp_dir.path().join("plain.txt");
        let crypt_path = temp_dir.path().join("crypt.txt.saltybox");
        let decrypted_path = output_dir.join("decrypted.txt");

        fs::create_dir(&output_dir).unwrap();
        fs::write(&plain_path, b"secret").unwrap();
        fs::write(&decrypted_path, b"old plaintext").unwrap();

        let mut reader = ConstantPassphraseReader::new(b"test".to_vec());
        encrypt_with_default_engine(&plain_path, &crypt_path, &mut reader).unwrap();

        let original_permissions = fs::metadata(&output_dir).unwrap().permissions();
        let mut unwritable_permissions = original_permissions.clone();
        unwritable_permissions.set_mode(0o500);
        fs::set_permissions(&output_dir, unwritable_permissions).unwrap();

        let probe_path = output_dir.join("write-probe");
        if fs::write(&probe_path, b"probe").is_ok() {
            fs::set_permissions(&output_dir, original_permissions).unwrap();
            fs::remove_file(probe_path).unwrap();
            eprintln!("skipping write-failure assertion because this process can still write");
            return;
        }

        let mut reader = ConstantPassphraseReader::new(b"test".to_vec());
        let result = decrypt_file(&crypt_path, &decrypted_path, &mut reader);

        fs::set_permissions(&output_dir, original_permissions).unwrap();

        result.expect_err("expected decrypt output write to fail");
        assert_eq!(fs::read(&decrypted_path).unwrap(), b"old plaintext");
    }

    /// Pins the pre-write framing SPEC.md makes normative for failures
    /// before the tempfile exists: an output directory that cannot be opened
    /// (mode 0o000 here, so EACCES rather than the specially-handled
    /// NotFound) must be reported as a failure while preparing to write. The
    /// pre-fix message claimed the file had already been written, sending
    /// users hunting for output that never existed. (SPEC's "leave nothing
    /// behind" clause is not asserted here: with the directory unwritable,
    /// no implementation could leave anything behind, so such an assertion
    /// would be vacuous.)
    #[test]
    #[cfg(unix)]
    fn test_unopenable_output_directory_reports_pre_write_failure() {
        let temp_dir = TempDir::new().unwrap();
        let output_dir = temp_dir.path().join("output");
        let plain_path = temp_dir.path().join("plain.txt");
        let crypt_path = output_dir.join("crypt.txt.saltybox");

        fs::create_dir(&output_dir).unwrap();
        fs::write(&plain_path, b"secret").unwrap();

        let original_permissions = fs::metadata(&output_dir).unwrap().permissions();
        let mut unopenable_permissions = original_permissions.clone();
        unopenable_permissions.set_mode(0o000);
        fs::set_permissions(&output_dir, unopenable_permissions).unwrap();

        // Root ignores directory permissions; skip rather than assert a
        // failure that cannot happen (same pattern as the write-failure test
        // above).
        if fs::File::open(&output_dir).is_ok() {
            fs::set_permissions(&output_dir, original_permissions).unwrap();
            eprintln!(
                "skipping unopenable-directory assertion because this process can still open it"
            );
            return;
        }

        let mut reader = ConstantPassphraseReader::new(b"test".to_vec());
        let result = encrypt_with_default_engine(&plain_path, &crypt_path, &mut reader);

        fs::set_permissions(&output_dir, original_permissions).unwrap();

        let err = result.expect_err("expected unopenable output directory to fail");
        let mut found_pre_write_framing = false;
        let mut source: Option<&(dyn std::error::Error + 'static)> = Some(&err);
        while let Some(e) = source {
            let msg = e.to_string();
            assert!(
                !msg.contains("after writing"),
                "message must not claim a write happened: {msg}"
            );
            if msg.contains("while preparing to write") {
                found_pre_write_framing = true;
            }
            source = e.source();
        }
        assert!(
            found_pre_write_framing,
            "expected the pre-write framing in the error chain"
        );
    }

    /// Pins the tempfile contract SPEC.md makes normative: the temporary file
    /// is created in the output directory, named with the `.saltybox-` prefix
    /// and `.tmp` suffix, and on Unix is owner-only from the start. A tempfile
    /// left behind by a crash must be recognizable by name, and must not be
    /// readable by other users while it holds plaintext.
    #[test]
    fn test_create_tempfile_is_private_and_named_per_spec() {
        let temp_dir = TempDir::new().unwrap();
        let temp_file = create_tempfile(temp_dir.path()).unwrap();
        let path = temp_file.path();

        assert_eq!(path.parent().unwrap(), temp_dir.path());
        let name = path.file_name().unwrap().to_str().unwrap();
        assert!(name.starts_with(".saltybox-"), "name: {name}");
        assert!(name.ends_with(".tmp"), "name: {name}");
        #[cfg(unix)]
        {
            let mode = fs::metadata(path).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600, "tempfile must be owner-only");
        }
    }

    /// A failed rename onto the output path is a user error and leaves no
    /// tempfile behind, even while the caller still holds the error.
    ///
    /// SPEC.md classifies failures on user-supplied paths as user errors and
    /// promises that failures the command detects after creating the
    /// tempfile remove it; for `decrypt` a leftover would be a stray
    /// plaintext copy. The directory is inspected while `err` is alive on
    /// purpose: removal must happen at the failure site, not whenever the
    /// error's owner drops it. The rename is forced to fail by making the
    /// output path an existing directory. The check compares the directory's
    /// full contents so it does not depend on the tempfile naming scheme.
    #[test]
    fn test_failed_rename_removes_tempfile_and_is_user_error() {
        let temp_dir = TempDir::new().unwrap();
        let plain_path = temp_dir.path().join("plain.txt");
        let crypt_path = temp_dir.path().join("occupied");

        fs::write(&plain_path, b"secret").unwrap();
        fs::create_dir(&crypt_path).unwrap();

        let mut reader = ConstantPassphraseReader::new(b"test".to_vec());
        let err = encrypt_with_default_engine(&plain_path, &crypt_path, &mut reader)
            .expect_err("expected rename onto a directory to fail");

        assert_eq!(err.category, ErrorCategory::User);
        assert_eq!(err.kind, Some(ErrorKind::Io));
        let mut chain = String::new();
        let mut source: Option<&(dyn std::error::Error + 'static)> = Some(&err);
        while let Some(e) = source {
            chain.push_str(&e.to_string());
            chain.push('\n');
            source = e.source();
        }
        assert!(
            chain.contains("failed to rename to target file"),
            "chain: {chain}"
        );
        let mut entries: Vec<_> = fs::read_dir(temp_dir.path())
            .unwrap()
            .map(|entry| entry.unwrap().file_name().into_string().unwrap())
            .collect();
        entries.sort();
        assert_eq!(entries, ["occupied", "plain.txt"]);
    }

    /// When removing the tempfile after a failure itself fails, the error
    /// names the leftover file so the user can remove it by hand.
    ///
    /// This is the only way a tempfile outlives an in-process failure, and
    /// for `decrypt` it holds plaintext, so SPEC.md requires the path to be
    /// reported rather than dropped. Removal is made to fail by taking write
    /// permission away from the directory holding the tempfile. The original
    /// failure must survive as the cause, keeping its category.
    #[test]
    #[cfg(unix)]
    fn test_discard_tempfile_reports_failed_removal() {
        let temp_dir = TempDir::new().unwrap();
        let dir = temp_dir.path().join("locked");
        fs::create_dir(&dir).unwrap();
        let temp_file = NamedTempFile::new_in(&dir).unwrap();
        let tempfile_path = temp_file.path().to_path_buf();

        let original_permissions = fs::metadata(&dir).unwrap().permissions();
        let mut locked_permissions = original_permissions.clone();
        locked_permissions.set_mode(0o500);
        fs::set_permissions(&dir, locked_permissions).unwrap();

        // Root ignores directory permissions; skip rather than assert a
        // failure that cannot happen (same pattern as the tests above).
        let probe = dir.join("probe");
        if fs::write(&probe, b"").is_ok() {
            fs::remove_file(&probe).unwrap();
            fs::set_permissions(&dir, original_permissions).unwrap();
            eprintln!("skipping failed-removal assertion because this process can still write");
            return;
        }

        let original = SaltyboxError::with_kind(
            ErrorCategory::Internal,
            ErrorKind::Io,
            "failed to sync out.txt",
        );
        let err = discard_tempfile(temp_file, original);
        fs::set_permissions(&dir, original_permissions).unwrap();

        let msg = err.to_string();
        assert!(
            msg.contains(&tempfile_path.display().to_string()),
            "msg: {msg}"
        );
        assert!(msg.contains("remove it by hand"), "msg: {msg}");
        assert_eq!(err.category, ErrorCategory::Internal);
        let cause = std::error::Error::source(&err).expect("original failure as cause");
        assert_eq!(cause.to_string(), "failed to sync out.txt");
        assert!(tempfile_path.exists(), "the file should still be there");
    }

    /// A tempfile that is already gone when cleanup runs counts as removed:
    /// reporting a leftover that does not exist would send the user looking
    /// for a plaintext copy that is not there.
    #[test]
    fn test_discard_tempfile_treats_missing_file_as_removed() {
        let temp_dir = TempDir::new().unwrap();
        let temp_file = NamedTempFile::new_in(temp_dir.path()).unwrap();
        fs::remove_file(temp_file.path()).unwrap();

        let original = SaltyboxError::with_kind(
            ErrorCategory::Internal,
            ErrorKind::Io,
            "failed to write out.txt",
        );
        let err = discard_tempfile(temp_file, original);

        assert_eq!(err.to_string(), "failed to write out.txt");
        assert!(std::error::Error::source(&err).is_none());
    }

    /// An empty output path is rejected by name as a user error, with the
    /// unset-shell-variable hint, before anything is written.
    ///
    /// The realistic way to get here is `-o "$OUT"` with the variable unset,
    /// the same mistake SPEC.md calls out for empty passphrases, and SPEC.md
    /// promises the rejection says so. Before the dedicated check the empty
    /// path fell through to the parent-directory lookup and was reported as
    /// "no parent directory", a description of the mechanism rather than the
    /// mistake. That nothing is written is not asserted: an empty path has
    /// no directory to inspect short of the process working directory, and
    /// the check runs before any tempfile is created.
    #[test]
    fn test_encrypt_to_empty_output_path_is_user_error() {
        let temp_dir = TempDir::new().unwrap();
        let plain_path = temp_dir.path().join("plain.txt");
        fs::write(&plain_path, b"secret").unwrap();

        let mut reader = ConstantPassphraseReader::new(b"test".to_vec());
        let result = encrypt_with_default_engine(&plain_path, Path::new(""), &mut reader);

        let err = result.expect_err("expected empty output path failure");
        assert_eq!(err.category, ErrorCategory::User);
        assert_eq!(err.kind, Some(ErrorKind::Io));
        let mut found = false;
        let mut source: Option<&(dyn std::error::Error + 'static)> = Some(&err);
        while let Some(e) = source {
            if e.to_string()
                == "empty output path is not allowed (note that an unset shell variable expands to empty)"
            {
                found = true;
            }
            source = e.source();
        }
        assert!(
            found,
            "expected the empty-output-path diagnostic in the chain: {err}"
        );
    }

    /// An output path ending in a separator is rejected by the up-front path
    /// check, before any output-path I/O or tempfile creation, for `encrypt`.
    ///
    /// `Path::parent` ignores the trailing separator, so without the check
    /// `nodir/` resolved its directory to the path's parent, created a
    /// tempfile holding the output (plaintext, for `decrypt`) there, and only
    /// failed at the rename with an error that did not name the cause. The
    /// tempfile cleanup would also leave no tempfile behind, so the absence of
    /// a source error is what proves the rejection happens up front rather
    /// than at the failed rename. The path lives under a scratch directory so
    /// the test never touches the process working directory.
    #[test]
    fn test_encrypt_to_path_ending_in_separator_is_rejected_up_front() {
        let temp_dir = TempDir::new().unwrap();
        let plain_path = temp_dir.path().join("plain.txt");
        fs::write(&plain_path, b"secret").unwrap();
        let crypt_path = temp_dir.path().join("nodir/");

        let mut reader = ConstantPassphraseReader::new(b"test".to_vec());
        let err = encrypt_with_default_engine(&plain_path, &crypt_path, &mut reader)
            .expect_err("expected trailing-separator output path failure");

        assert_eq!(err.category, ErrorCategory::User);
        assert_eq!(err.kind, Some(ErrorKind::Io));
        assert!(
            err.to_string().contains("ends in a path separator"),
            "msg: {err}"
        );
        assert!(
            std::error::Error::source(&err).is_none(),
            "rejected by the path check, not by a failed I/O call"
        );
        let entries: Vec<_> = fs::read_dir(temp_dir.path())
            .unwrap()
            .map(|entry| entry.unwrap().file_name().into_string().unwrap())
            .collect();
        assert_eq!(entries, ["plain.txt"]);
    }

    /// Every command rejects a bad output path before it reads its input or
    /// asks for a passphrase.
    ///
    /// The path check only looks at the argument, so it runs first: a bad
    /// `-o` must not make the user type a passphrase and wait out key
    /// derivation first. The input path here does not exist, so a read before
    /// the check would surface as a read error instead, and the reader panics
    /// if asked for a passphrase. Both the empty path and a trailing
    /// separator are covered, for `encrypt`, `decrypt` and `update`.
    #[test]
    fn test_bad_output_path_is_rejected_before_input_read_and_prompt() {
        struct PanickingReader;
        impl PassphraseReader for PanickingReader {
            fn read_passphrase(&mut self) -> Result<Zeroizing<Vec<u8>>> {
                panic!("the passphrase must not be requested before the output path is checked");
            }
        }

        let temp_dir = TempDir::new().unwrap();
        let missing_input = temp_dir.path().join("missing-input");
        let trailing = temp_dir.path().join("nodir/");
        for (output, expected) in [
            (Path::new(""), "empty output path is not allowed"),
            (trailing.as_path(), "ends in a path separator"),
        ] {
            let results = [
                encrypt_with_default_engine(&missing_input, output, &mut PanickingReader),
                decrypt_file(&missing_input, output, &mut PanickingReader),
                update_with_default_engine(&missing_input, output, &mut PanickingReader),
            ];
            for result in results {
                let err = result.expect_err("expected output path rejection");
                assert!(err.to_string().contains(expected), "msg: {err}");
                assert!(std::error::Error::source(&err).is_none());
            }
        }
    }

    /// `update` rejects an output path ending in a separator with the same
    /// specific message, instead of failing first on reading the existing
    /// file (which is what happened before it ran the path check itself).
    /// SPEC.md promises the rejection for every command.
    #[test]
    fn test_update_to_path_ending_in_separator_is_rejected_up_front() {
        let temp_dir = TempDir::new().unwrap();
        let plain_path = temp_dir.path().join("plain.txt");
        fs::write(&plain_path, b"secret").unwrap();
        let crypt_path = temp_dir.path().join("nodir/");

        let mut reader = ConstantPassphraseReader::new(b"test".to_vec());
        let err = update_with_default_engine(&plain_path, &crypt_path, &mut reader)
            .expect_err("expected trailing-separator output path failure");

        assert_eq!(err.category, ErrorCategory::User);
        assert_eq!(err.kind, Some(ErrorKind::Io));
        assert!(
            err.to_string().contains("ends in a path separator"),
            "msg: {err}"
        );
        assert!(std::error::Error::source(&err).is_none());
    }

    /// `update` rejects an empty output path with the empty-path message
    /// rather than a generic error from reading "" as the existing file.
    /// SPEC.md promises that rejection for every command; this pins that
    /// `update` runs the path check before its read.
    #[test]
    fn test_update_to_empty_output_path_is_rejected_up_front() {
        let temp_dir = TempDir::new().unwrap();
        let plain_path = temp_dir.path().join("plain.txt");
        fs::write(&plain_path, b"secret").unwrap();

        let mut reader = ConstantPassphraseReader::new(b"test".to_vec());
        let err = update_with_default_engine(&plain_path, Path::new(""), &mut reader)
            .expect_err("expected empty output path failure");

        assert_eq!(err.category, ErrorCategory::User);
        assert_eq!(err.kind, Some(ErrorKind::Io));
        assert!(
            err.to_string().contains("empty output path is not allowed"),
            "msg: {err}"
        );
        assert!(std::error::Error::source(&err).is_none());
    }

    /// A typoed output directory is a user error, and on Unix the message
    /// names the directory and says it does not exist.
    ///
    /// SPEC.md promises a nonexistent output directory "is reported as such",
    /// which is a promise about the wording: the classification alone would
    /// still hold if the specific pre-check regressed to the generic
    /// tempfile-creation failure, and only the message assertion catches
    /// that. The wording comes from the Unix-only directory open that runs
    /// before anything is written, hence the gate; Windows is unsupported.
    #[test]
    fn test_encrypt_to_missing_output_directory_is_user_error() {
        let temp_dir = TempDir::new().unwrap();
        let plain_path = temp_dir.path().join("plain.txt");
        let output_dir = temp_dir.path().join("no-such-dir");
        let crypt_path = output_dir.join("crypt.txt.saltybox");

        fs::write(&plain_path, b"secret").unwrap();

        let mut reader = ConstantPassphraseReader::new(b"test".to_vec());
        let result = encrypt_with_default_engine(&plain_path, &crypt_path, &mut reader);

        let err = result.expect_err("expected missing output directory failure");
        assert_eq!(err.category, ErrorCategory::User);
        assert_eq!(err.kind, Some(ErrorKind::Io));

        // The specific diagnostic sits below the "failed to write to"
        // context the encrypt path adds, so look for it in the chain.
        #[cfg(unix)]
        {
            let expected = format!("output directory {} does not exist", output_dir.display());
            let mut source: Option<&(dyn std::error::Error + 'static)> = Some(&err);
            let mut found = false;
            while let Some(e) = source {
                if e.to_string() == expected {
                    found = true;
                }
                source = e.source();
            }
            assert!(found, "expected {expected:?} in the error chain: {err}");
        }
    }

    /// A directory given as the input file is a user error, not internal.
    ///
    /// Reading a directory fails with something other than NotFound, so this
    /// pins the half of SPEC.md's rule the nonexistent-input test does not:
    /// every I/O failure on a user-supplied path is the user's, not just a
    /// missing file. Before the rule, only NotFound was classified User and
    /// this case was Internal. The CLI-level test cannot observe the
    /// category; both produce the same nonzero exit.
    #[test]
    fn test_read_of_directory_as_input_is_user_error() {
        let temp_dir = TempDir::new().unwrap();
        let decrypted_path = temp_dir.path().join("decrypted.txt");

        let mut reader = ConstantPassphraseReader::new(b"test".to_vec());
        let result = decrypt_file(temp_dir.path(), &decrypted_path, &mut reader);

        let err = result.expect_err("expected directory-as-input failure");
        assert_eq!(err.category, ErrorCategory::User);
        assert_eq!(err.kind, Some(ErrorKind::Io));
        assert!(!decrypted_path.exists());
    }

    #[test]
    fn test_read_of_nonexistent_input_is_user_error() {
        // Pins the NotFound half of SPEC.md's rule that I/O failures on
        // user-supplied paths are user errors: a typoed input path is a user
        // mistake, not an internal failure. The CLI-level test cannot
        // observe the category; both produce the same nonzero exit.
        let temp_dir = TempDir::new().unwrap();
        let missing_path = temp_dir.path().join("no-such-file.saltybox");
        let decrypted_path = temp_dir.path().join("decrypted.txt");

        let mut reader = ConstantPassphraseReader::new(b"test".to_vec());
        let result = decrypt_file(&missing_path, &decrypted_path, &mut reader);

        let err = result.expect_err("expected missing input file failure");
        assert_eq!(err.category, ErrorCategory::User);
        assert_eq!(err.kind, Some(ErrorKind::Io));
        assert!(!decrypted_path.exists());
    }

    #[test]
    fn test_decrypt_wrong_passphrase() {
        let temp_dir = TempDir::new().unwrap();
        let plain_path = temp_dir.path().join("plain.txt");
        let crypt_path = temp_dir.path().join("crypt.txt.saltybox");
        let decrypted_path = temp_dir.path().join("decrypted.txt");

        fs::write(&plain_path, b"secret").unwrap();

        let mut reader = ConstantPassphraseReader::new(b"correct".to_vec());
        encrypt_with_default_engine(&plain_path, &crypt_path, &mut reader).unwrap();

        let mut reader = ConstantPassphraseReader::new(b"wrong".to_vec());
        let result = decrypt_file(&crypt_path, &decrypted_path, &mut reader);

        assert!(result.is_err());
        assert!(!decrypted_path.exists());
    }

    #[test]
    fn test_decrypt_wrong_passphrase_preserves_existing_output() {
        let temp_dir = TempDir::new().unwrap();
        let plain_path = temp_dir.path().join("plain.txt");
        let crypt_path = temp_dir.path().join("crypt.txt.saltybox");
        let decrypted_path = temp_dir.path().join("decrypted.txt");

        fs::write(&plain_path, b"secret").unwrap();
        fs::write(&decrypted_path, b"old plaintext").unwrap();

        let mut reader = ConstantPassphraseReader::new(b"correct".to_vec());
        encrypt_with_default_engine(&plain_path, &crypt_path, &mut reader).unwrap();

        let mut reader = ConstantPassphraseReader::new(b"wrong".to_vec());
        assert!(decrypt_file(&crypt_path, &decrypted_path, &mut reader).is_err());
        assert_eq!(fs::read(&decrypted_path).unwrap(), b"old plaintext");
    }

    #[test]
    fn test_decrypt_rejects_non_utf8_armored_input() {
        let temp_dir = TempDir::new().unwrap();
        let crypt_path = temp_dir.path().join("crypt.txt.saltybox");
        let decrypted_path = temp_dir.path().join("decrypted.txt");

        fs::write(&crypt_path, [0xff]).unwrap();

        let mut reader = ConstantPassphraseReader::new(b"test".to_vec());
        let result = decrypt_file(&crypt_path, &decrypted_path, &mut reader);

        let err = result.expect_err("expected UTF-8 rejection");
        assert_eq!(err.category, ErrorCategory::User);
        assert_eq!(err.kind, Some(ErrorKind::Io));
        assert_eq!(err.message(), "input file is not valid UTF-8");
        assert!(!decrypted_path.exists());
    }

    #[test]
    fn test_update_rejects_non_utf8_encrypted_input() {
        let temp_dir = TempDir::new().unwrap();
        let plain_path = temp_dir.path().join("plain.txt");
        let crypt_path = temp_dir.path().join("crypt.txt.saltybox");

        fs::write(&plain_path, b"new plaintext").unwrap();
        fs::write(&crypt_path, [0xff]).unwrap();

        let mut reader = ConstantPassphraseReader::new(b"test".to_vec());
        let result = update_with_default_engine(&plain_path, &crypt_path, &mut reader);

        let err = result.expect_err("expected UTF-8 rejection");
        assert_eq!(err.category, ErrorCategory::User);
        assert_eq!(err.kind, Some(ErrorKind::Io));
        assert_eq!(err.message(), "encrypted file is not valid UTF-8");
        assert_eq!(fs::read(&crypt_path).unwrap(), [0xff]);
    }

    /// A structurally malformed existing ciphertext aborts `update` with the
    /// same format diagnostic `decrypt` would give, and the file's bytes are
    /// left exactly as they were.
    ///
    /// SPEC.md promises that the validation read fails in the same scenarios
    /// as `decrypt`, with the same classifications, and that any such failure
    /// leaves the existing file unchanged. The wrong-passphrase and non-UTF-8
    /// tests pin two of those scenarios; this one pins the format-error class,
    /// which is otherwise only tested through `decrypt`. Uses a real
    /// ciphertext with its `:end` marker cut off so the input is valid UTF-8
    /// and reaches the armor check rather than failing earlier.
    #[test]
    fn test_update_rejects_malformed_encrypted_input_unchanged() {
        let temp_dir = TempDir::new().unwrap();
        let plain_path = temp_dir.path().join("plain.txt");
        let crypt_path = temp_dir.path().join("crypt.txt.saltybox");

        fs::write(&plain_path, b"Initial").unwrap();
        let mut reader = ConstantPassphraseReader::new(b"test".to_vec());
        encrypt_with_default_engine(&plain_path, &crypt_path, &mut reader).unwrap();

        let armored = fs::read_to_string(&crypt_path).unwrap();
        let truncated = armored
            .strip_suffix(":end")
            .expect("default engine output ends with the v2 marker");
        fs::write(&crypt_path, truncated).unwrap();

        fs::write(&plain_path, b"Updated").unwrap();
        let mut reader = ConstantPassphraseReader::new(b"test".to_vec());
        let result = update_with_default_engine(&plain_path, &crypt_path, &mut reader);

        let err = result.expect_err("expected armor rejection");
        assert_eq!(err.category, ErrorCategory::User);
        assert_eq!(err.kind, Some(ErrorKind::ArmoringInvalid));
        assert_eq!(fs::read_to_string(&crypt_path).unwrap(), truncated);
    }

    /// `update` validates the passphrase against the existing file BEFORE it
    /// reads the new plaintext: with a wrong passphrase and a missing
    /// plaintext file, the error is the authentication failure, not the I/O
    /// error.
    ///
    /// SPEC.md describes `update` as "validating first", and the order is
    /// user-visible only when both steps would fail. Nothing else in the
    /// suite would notice the two reads being swapped. Paired with
    /// `test_update_missing_plaintext_after_validation_leaves_file_unchanged`,
    /// which covers the correct-passphrase side of the same ordering.
    #[test]
    fn test_update_validates_passphrase_before_reading_plaintext() {
        let temp_dir = TempDir::new().unwrap();
        let plain_path = temp_dir.path().join("plain.txt");
        let missing_path = temp_dir.path().join("missing.txt");
        let crypt_path = temp_dir.path().join("crypt.txt.saltybox");

        fs::write(&plain_path, b"Initial").unwrap();
        let mut reader = ConstantPassphraseReader::new(b"correct password".to_vec());
        encrypt_with_default_engine(&plain_path, &crypt_path, &mut reader).unwrap();

        let mut reader = ConstantPassphraseReader::new(b"wrong password".to_vec());
        let result = update_with_default_engine(&missing_path, &crypt_path, &mut reader);

        let err = result.expect_err("expected authentication failure before plaintext read");
        assert_eq!(err.kind, Some(ErrorKind::AuthenticationFailed));
    }

    /// A missing new-plaintext file, discovered after the passphrase has
    /// validated, is a user I/O error and leaves the existing ciphertext
    /// byte-for-byte unchanged.
    ///
    /// This is the point in `update` where validation has succeeded and the
    /// only remaining failure is the user's own input path. The existing file
    /// must not be touched: the write happens only after the new plaintext is
    /// in hand. Companion to
    /// `test_update_validates_passphrase_before_reading_plaintext`.
    #[test]
    fn test_update_missing_plaintext_after_validation_leaves_file_unchanged() {
        let temp_dir = TempDir::new().unwrap();
        let plain_path = temp_dir.path().join("plain.txt");
        let missing_path = temp_dir.path().join("missing.txt");
        let crypt_path = temp_dir.path().join("crypt.txt.saltybox");

        fs::write(&plain_path, b"Initial").unwrap();
        let mut reader = ConstantPassphraseReader::new(b"correct password".to_vec());
        encrypt_with_default_engine(&plain_path, &crypt_path, &mut reader).unwrap();
        let before = fs::read(&crypt_path).unwrap();

        let mut reader = ConstantPassphraseReader::new(b"correct password".to_vec());
        let result = update_with_default_engine(&missing_path, &crypt_path, &mut reader);

        let err = result.expect_err("expected missing plaintext failure");
        assert_eq!(err.category, ErrorCategory::User);
        assert_eq!(err.kind, Some(ErrorKind::Io));
        assert_eq!(fs::read(&crypt_path).unwrap(), before);
    }

    /// Empty passphrases and passphrases containing a line break are
    /// rejected by every operation, including decrypt and update.
    ///
    /// Both are almost always a piping mistake (`echo -n "$PASS"` or
    /// `echo "$PASS"` with `PASS` unset). SPEC.md rejects them for every
    /// command, which deliberately makes files encrypted with such a
    /// passphrase by older versions undecryptable. `\r` is included so
    /// Windows-style line endings are caught, and line breaks are rejected
    /// wherever they appear, not just at the end.
    #[test]
    fn test_invalid_passphrases_are_rejected_by_all_operations() {
        let temp_dir = TempDir::new().unwrap();
        let plain_path = temp_dir.path().join("plain.txt");
        let crypt_path = temp_dir.path().join("crypt.txt.saltybox");
        let decrypted_path = temp_dir.path().join("decrypted.txt");
        fs::write(&plain_path, b"secret").unwrap();

        let cases: &[(&[u8], ErrorKind)] = &[
            (b"", ErrorKind::EmptyPassphrase),
            (b"\n", ErrorKind::PassphraseContainsLineBreak),
            (b"pw\n", ErrorKind::PassphraseContainsLineBreak),
            (b"pw\r\n", ErrorKind::PassphraseContainsLineBreak),
            (b"pw\r", ErrorKind::PassphraseContainsLineBreak),
            (b"p\nw", ErrorKind::PassphraseContainsLineBreak),
        ];
        for &(passphrase, kind) in cases {
            let mut reader = ConstantPassphraseReader::new(passphrase.to_vec());
            let err = encrypt_with_default_engine(&plain_path, &crypt_path, &mut reader)
                .expect_err("expected rejection on encrypt");
            assert_eq!(err.category, ErrorCategory::User);
            assert_eq!(err.kind, Some(kind), "encrypt, passphrase {passphrase:?}");
            assert!(!crypt_path.exists());
        }

        // A real encrypted file, so decrypt and update fail on the
        // passphrase check rather than on a missing input.
        let mut reader = ConstantPassphraseReader::new(b"real passphrase".to_vec());
        encrypt_with_default_engine(&plain_path, &crypt_path, &mut reader).unwrap();
        let existing = fs::read(&crypt_path).unwrap();
        for &(passphrase, kind) in cases {
            let mut reader = ConstantPassphraseReader::new(passphrase.to_vec());
            let err = decrypt_file(&crypt_path, &decrypted_path, &mut reader)
                .expect_err("expected rejection on decrypt");
            assert_eq!(err.category, ErrorCategory::User);
            assert_eq!(err.kind, Some(kind), "decrypt, passphrase {passphrase:?}");
            assert!(!decrypted_path.exists());

            let mut reader = ConstantPassphraseReader::new(passphrase.to_vec());
            let err = update_with_default_engine(&plain_path, &crypt_path, &mut reader)
                .expect_err("expected rejection on update");
            assert_eq!(err.category, ErrorCategory::User);
            assert_eq!(err.kind, Some(kind), "update, passphrase {passphrase:?}");
            assert_eq!(fs::read(&crypt_path).unwrap(), existing);
        }
    }

    /// An interactively confirmed passphrase whose two entries differ makes
    /// `encrypt` fail as a user error and write nothing.
    ///
    /// The terminal prompt reads with echo disabled, so without the second
    /// entry a typo would silently become the passphrase of a file nobody can
    /// decrypt, found out only when decryption fails. SPEC.md requires the
    /// confirmation for interactive `encrypt`.
    #[test]
    fn test_encrypt_rejects_mismatched_confirmation() {
        let temp_dir = TempDir::new().unwrap();
        let plain_path = temp_dir.path().join("plain.txt");
        let crypt_path = temp_dir.path().join("crypt.txt.saltybox");
        fs::write(&plain_path, b"secret").unwrap();

        let mut reader =
            ConfirmingPassphraseReader::new(b"correct horse".to_vec(), b"correct hose".to_vec());
        let err = encrypt_with_default_engine(&plain_path, &crypt_path, &mut reader)
            .expect_err("expected mismatched confirmation to fail");

        assert_eq!(err.category, ErrorCategory::User);
        assert_eq!(err.kind, Some(ErrorKind::PassphraseConfirmationMismatch));
        assert_eq!(
            err.message(),
            "passphrase entries do not match; nothing was written"
        );
        assert!(!crypt_path.exists());
    }

    /// A matching confirmation lets `encrypt` proceed, and the file decrypts
    /// with that passphrase. This guards against the confirmation step
    /// rejecting, or altering, a correctly repeated passphrase.
    #[test]
    fn test_encrypt_accepts_matching_confirmation() {
        let temp_dir = TempDir::new().unwrap();
        let plain_path = temp_dir.path().join("plain.txt");
        let crypt_path = temp_dir.path().join("crypt.txt.saltybox");
        let decrypted_path = temp_dir.path().join("decrypted.txt");
        fs::write(&plain_path, b"secret").unwrap();

        let mut reader =
            ConfirmingPassphraseReader::new(b"correct horse".to_vec(), b"correct horse".to_vec());
        encrypt_with_default_engine(&plain_path, &crypt_path, &mut reader).unwrap();

        let mut reader = ConstantPassphraseReader::new(b"correct horse".to_vec());
        decrypt_file(&crypt_path, &decrypted_path, &mut reader).unwrap();
        assert_eq!(fs::read(&decrypted_path).unwrap(), b"secret");
    }

    /// `decrypt` and `update` never ask for a confirmation: the existing file
    /// already confirms the passphrase there, and SPEC.md rules out a second
    /// prompt. The reader panics if asked, so a regression that asked (which
    /// interactively means a surprise second prompt) fails the test.
    #[test]
    fn test_decrypt_and_update_do_not_confirm() {
        struct NoConfirmReader;
        impl PassphraseReader for NoConfirmReader {
            fn read_passphrase(&mut self) -> Result<Zeroizing<Vec<u8>>> {
                Ok(Zeroizing::new(b"pw".to_vec()))
            }
            fn read_confirmation(&mut self) -> Result<Option<Zeroizing<Vec<u8>>>> {
                panic!("decrypt and update must not ask for a confirmation");
            }
        }

        let temp_dir = TempDir::new().unwrap();
        let plain_path = temp_dir.path().join("plain.txt");
        let crypt_path = temp_dir.path().join("crypt.txt.saltybox");
        let decrypted_path = temp_dir.path().join("decrypted.txt");
        fs::write(&plain_path, b"secret").unwrap();
        let mut reader = ConstantPassphraseReader::new(b"pw".to_vec());
        encrypt_with_default_engine(&plain_path, &crypt_path, &mut reader).unwrap();

        decrypt_file(&crypt_path, &decrypted_path, &mut NoConfirmReader).unwrap();
        update_with_default_engine(&plain_path, &crypt_path, &mut NoConfirmReader).unwrap();
    }

    #[test]
    fn test_empty_file() {
        let temp_dir = TempDir::new().unwrap();
        let plain_path = temp_dir.path().join("empty.txt");
        let crypt_path = temp_dir.path().join("empty.txt.saltybox");
        let decrypted_path = temp_dir.path().join("decrypted.txt");

        fs::write(&plain_path, b"").unwrap();

        let mut reader = ConstantPassphraseReader::new(b"test".to_vec());
        encrypt_with_default_engine(&plain_path, &crypt_path, &mut reader).unwrap();

        let mut reader = ConstantPassphraseReader::new(b"test".to_vec());
        decrypt_file(&crypt_path, &decrypted_path, &mut reader).unwrap();

        let decrypted = fs::read(&decrypted_path).unwrap();
        assert_eq!(decrypted, b"");
    }
}
