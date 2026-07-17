//! File encryption/decryption operations
//!
//! This module provides high-level file operations for encrypting, decrypting,
//! and updating files using the saltybox format.

use crate::error::{ErrorCategory, ErrorKind, Result, SaltyboxError};
use crate::format;
use crate::passphrase::PassphraseReader;
use std::fs;
use std::io::{self, Write};
use std::path::Path;
use zeroize::Zeroizing;

const TEMPFILE_PREFIX: &str = ".saltybox-";
const TEMPFILE_SUFFIX: &str = ".tmp";

/// Reads the passphrase and rejects an empty one.
///
/// Empty passphrases are refused for all operations. An empty passphrase
/// provides no meaningful protection, and empty input is almost always an
/// accident rather than intent — the canonical case is `--passphrase-stdin`
/// fed by `echo -n "$PASS"` with `PASS` unset, which expands to zero bytes
/// and would otherwise silently produce an effectively unprotected file.
///
/// The check lives here at the operation layer, not in the individual
/// [`PassphraseReader`] implementations, so it holds regardless of how the
/// passphrase was obtained.
fn read_nonempty_passphrase(reader: &mut dyn PassphraseReader) -> Result<Zeroizing<Vec<u8>>> {
    let passphrase = reader.read_passphrase()?;
    if passphrase.is_empty() {
        return Err(SaltyboxError::with_kind(
            ErrorCategory::User,
            ErrorKind::EmptyPassphrase,
            "empty passphrase is not allowed (note that an unset shell variable expands to empty)",
        ));
    }
    Ok(passphrase)
}

/// Encrypt a file with a passphrase
///
/// Reads plaintext from `input_path`, encrypts it using a passphrase from
/// `passphrase_reader`, and writes the armored ciphertext to `output_path`.
///
/// Which format is written is the caller's choice via `write_engine`; the
/// CLI always passes [`format::default_write_engine`].
///
/// Output is written atomically via a same-directory temporary file.
/// On Unix systems, the final file mode is set to 0o600 (read/write for owner only).
pub fn encrypt_file(
    input_path: &Path,
    output_path: &Path,
    passphrase_reader: &mut dyn PassphraseReader,
    write_engine: &dyn format::FormatEngine,
) -> Result<()> {
    let plaintext = Zeroizing::new(fs::read(input_path).map_err(|e| read_error(input_path, e))?);
    let passphrase = read_nonempty_passphrase(passphrase_reader)?;
    let armored = write_engine
        .encrypt(&passphrase, &plaintext)
        .map_err(|e| e.with_context("encryption failed"))?;
    write_file_secure(output_path, armored.as_bytes())
        .map_err(|e| e.with_context(format!("failed to write to {}", output_path.display())))?;

    Ok(())
}

/// Decrypt a file with a passphrase
///
/// Reads armored ciphertext from `input_path`, decrypts it using a passphrase from
/// `passphrase_reader`, and writes the plaintext to `output_path`.
///
/// Output is written atomically via a same-directory temporary file.
/// On Unix systems, the final file mode is set to 0o600 (read/write for owner only).
pub fn decrypt_file(
    input_path: &Path,
    output_path: &Path,
    passphrase_reader: &mut dyn PassphraseReader,
) -> Result<()> {
    let armored_bytes = fs::read(input_path).map_err(|e| read_error(input_path, e))?;
    let armored = String::from_utf8(armored_bytes).map_err(|e| {
        SaltyboxError::with_kind_and_source(
            ErrorCategory::User,
            ErrorKind::Io,
            "input file is not valid UTF-8",
            e,
        )
    })?;
    let passphrase = read_nonempty_passphrase(passphrase_reader)?;
    let (engine, ciphertext) =
        format::decode(&armored).map_err(|e| e.with_context("failed to unarmor"))?;
    let plaintext = engine
        .decrypt(&passphrase, &ciphertext)
        .map_err(|e| e.with_context("failed to decrypt"))?;
    write_file_secure(output_path, &plaintext)
        .map_err(|e| e.with_context(format!("failed to write to {}", output_path.display())))?;
    Ok(())
}

/// Update an encrypted file with new plaintext using the same passphrase
///
/// This function:
/// 1. Decrypts the existing file at `crypt_path` to validate the passphrase
/// 2. Reads new plaintext from `plain_path`
/// 3. Encrypts the new plaintext with the validated passphrase
/// 4. Atomically writes to `crypt_path` (tempfile + fsync + rename)
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
    let passphrase = read_nonempty_passphrase(passphrase_reader)?;

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
    write_file_secure(crypt_path, new_armored.as_bytes())?;
    Ok(())
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

/// Replaces a file through a private same-directory temporary file.
///
/// Successful writes sync the tempfile contents on every platform; on Unix
/// they additionally sync the containing directory so the replacement
/// survives crashes that happen after rename returns. On Unix the resulting
/// file mode is `0600`.
fn write_file_secure(path: &Path, contents: &[u8]) -> Result<()> {
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
        SaltyboxError::with_kind_and_source(path_error_category(&e), ErrorKind::Io, msg, e)
    })?;
    let mut temp_file = tempfile::Builder::new()
        .prefix(TEMPFILE_PREFIX)
        .suffix(TEMPFILE_SUFFIX)
        .tempfile_in(output_dir)
        .map_err(|e| {
            SaltyboxError::with_kind_and_source(
                path_error_category(&e),
                ErrorKind::Io,
                format!("failed to create tempfile for {}", path.display()),
                e,
            )
        })?;

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

    temp_file.persist(path).map_err(|e| {
        let tempfile_path = e.file.path().display().to_string();
        SaltyboxError::with_kind_and_source(
            ErrorCategory::Internal,
            ErrorKind::Io,
            format!(
                "failed to rename to target file {}; tempfile may still exist at {} and may need manual removal",
                path.display(),
                tempfile_path
            ),
            e,
        )
    })?;
    #[cfg(unix)]
    {
        // The file sync above covers the bytes. The directory sync makes the
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

/// Categorizes a failed I/O operation on a user-supplied path.
///
/// A missing path is a user mistake (typoed input file or output directory);
/// anything else is unexpected and treated as internal. Used on both the
/// read and write sides so the same mistake gets the same categorization.
fn path_error_category(err: &io::Error) -> ErrorCategory {
    if err.kind() == io::ErrorKind::NotFound {
        ErrorCategory::User
    } else {
        ErrorCategory::Internal
    }
}

fn read_error(path: &Path, err: io::Error) -> SaltyboxError {
    SaltyboxError::with_kind_and_source(
        path_error_category(&err),
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
    use crate::passphrase::ConstantPassphraseReader;
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

    /// Pins the tempfile contract SPEC.md makes normative: the temporary
    /// file is created in the output directory with the ".saltybox-" prefix
    /// and owner-only permissions, and a failed rename reports the
    /// tempfile's path so the user can clean it up. The rename is forced to
    /// fail by making the output path an existing directory.
    #[test]
    #[cfg(unix)]
    fn test_failed_rename_reports_private_tempfile() {
        let temp_dir = TempDir::new().unwrap();
        let plain_path = temp_dir.path().join("plain.txt");
        let crypt_path = temp_dir.path().join("occupied");

        fs::write(&plain_path, b"secret").unwrap();
        fs::create_dir(&crypt_path).unwrap();

        let mut reader = ConstantPassphraseReader::new(b"test".to_vec());
        let err = encrypt_with_default_engine(&plain_path, &crypt_path, &mut reader)
            .expect_err("expected rename onto a directory to fail");

        // The rename-failure message travels in the error source chain and
        // must point at the leftover tempfile.
        let mut chain_msg = None;
        let mut source: Option<&(dyn std::error::Error + 'static)> = Some(&err);
        while let Some(e) = source {
            let msg = e.to_string();
            if msg.contains("tempfile may still exist at") {
                chain_msg = Some(msg);
                break;
            }
            source = e.source();
        }
        let msg = chain_msg.expect("expected rename failure to report the tempfile path");
        let tempfile_path = msg
            .split("tempfile may still exist at ")
            .nth(1)
            .and_then(|rest| rest.split(" and may need manual removal").next())
            .expect("expected the message to embed the tempfile path");

        let tempfile_path = std::path::Path::new(tempfile_path);
        assert!(tempfile_path.exists(), "leftover tempfile should exist");
        let name = tempfile_path.file_name().unwrap().to_str().unwrap();
        assert!(name.starts_with(".saltybox-"), "name: {name}");
        assert!(name.ends_with(".tmp"), "name: {name}");
        assert_eq!(tempfile_path.parent().unwrap(), temp_dir.path());

        let mode = fs::metadata(tempfile_path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600, "tempfile must be owner-only");
    }

    #[test]
    fn test_encrypt_to_missing_output_directory_is_user_error() {
        let temp_dir = TempDir::new().unwrap();
        let plain_path = temp_dir.path().join("plain.txt");
        let crypt_path = temp_dir
            .path()
            .join("no-such-dir")
            .join("crypt.txt.saltybox");

        fs::write(&plain_path, b"secret").unwrap();

        let mut reader = ConstantPassphraseReader::new(b"test".to_vec());
        let result = encrypt_with_default_engine(&plain_path, &crypt_path, &mut reader);

        let err = result.expect_err("expected missing output directory failure");
        assert_eq!(err.category, ErrorCategory::User);
        assert_eq!(err.kind, Some(ErrorKind::Io));
    }

    #[test]
    fn test_read_of_nonexistent_input_is_user_error() {
        // Pins read_error's NotFound categorization: a typoed input path is a
        // user mistake, not an internal failure. The CLI-level test cannot
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

    /// Empty passphrases are rejected by every operation, including decrypt:
    /// SPEC.md makes files encrypted with an empty passphrase (possible in
    /// older versions) deliberately undecryptable.
    #[test]
    fn test_empty_passphrase_is_rejected_by_all_operations() {
        let temp_dir = TempDir::new().unwrap();
        let plain_path = temp_dir.path().join("plain.txt");
        let crypt_path = temp_dir.path().join("crypt.txt.saltybox");
        let decrypted_path = temp_dir.path().join("decrypted.txt");

        fs::write(&plain_path, b"secret").unwrap();

        let mut reader = ConstantPassphraseReader::new(b"".to_vec());
        let err = encrypt_with_default_engine(&plain_path, &crypt_path, &mut reader)
            .expect_err("expected empty passphrase rejection on encrypt");
        assert_eq!(err.category, ErrorCategory::User);
        assert_eq!(err.kind, Some(ErrorKind::EmptyPassphrase));
        assert!(!crypt_path.exists());

        // Set up a real encrypted file so decrypt/update fail on the
        // passphrase check, not on a missing input.
        let mut reader = ConstantPassphraseReader::new(b"real passphrase".to_vec());
        encrypt_with_default_engine(&plain_path, &crypt_path, &mut reader).unwrap();

        let mut reader = ConstantPassphraseReader::new(b"".to_vec());
        let err = decrypt_file(&crypt_path, &decrypted_path, &mut reader)
            .expect_err("expected empty passphrase rejection on decrypt");
        assert_eq!(err.kind, Some(ErrorKind::EmptyPassphrase));
        assert!(!decrypted_path.exists());

        let mut reader = ConstantPassphraseReader::new(b"".to_vec());
        let err = update_with_default_engine(&plain_path, &crypt_path, &mut reader)
            .expect_err("expected empty passphrase rejection on update");
        assert_eq!(err.kind, Some(ErrorKind::EmptyPassphrase));
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
