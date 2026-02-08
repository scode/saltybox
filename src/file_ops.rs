//! File encryption/decryption operations
//!
//! This module provides high-level file operations for encrypting, decrypting,
//! and updating files using the saltybox format.

use crate::error::{ErrorCategory, ErrorKind, Result, SaltyboxError};
use crate::passphrase::PassphraseReader;
use crate::secretcrypt;
use crate::varmor;
use std::fs;
use std::io::{self, Write};
use std::path::Path;

const TEMPFILE_PREFIX: &str = ".saltybox-";
const TEMPFILE_SUFFIX: &str = ".tmp";

/// Encrypt a file with a passphrase
///
/// Reads plaintext from `input_path`, encrypts it using a passphrase from
/// `passphrase_reader`, and writes the armored ciphertext to `output_path`.
///
/// Output is written atomically via a same-directory temporary file.
/// On Unix systems, the final file mode is set to 0o600 (read/write for owner only).
pub fn encrypt_file(
    input_path: &Path,
    output_path: &Path,
    passphrase_reader: &mut dyn PassphraseReader,
) -> Result<()> {
    let plaintext = fs::read(input_path).map_err(|e| read_error(input_path, e))?;
    let passphrase = passphrase_reader.read_passphrase()?;
    let ciphertext = secretcrypt::encrypt(&passphrase, &plaintext)
        .map_err(|e| e.with_context("encryption failed"))?;
    let armored = varmor::wrap(&ciphertext);
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
    let passphrase = passphrase_reader.read_passphrase()?;
    let ciphertext = varmor::unwrap(&armored).map_err(|e| e.with_context("failed to unarmor"))?;
    let plaintext = secretcrypt::decrypt(&passphrase, &ciphertext)
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
pub fn update_file(
    plain_path: &Path,
    crypt_path: &Path,
    passphrase_reader: &mut dyn PassphraseReader,
) -> Result<()> {
    let armored_bytes = fs::read(crypt_path).map_err(|e| read_error(crypt_path, e))?;
    let armored = String::from_utf8(armored_bytes).map_err(|e| {
        SaltyboxError::with_kind_and_source(
            ErrorCategory::User,
            ErrorKind::Io,
            "encrypted file is not valid UTF-8",
            e,
        )
    })?;
    let passphrase = passphrase_reader.read_passphrase()?;

    // Validate passphrase by decrypting existing file (discard plaintext)
    let ciphertext = varmor::unwrap(&armored).map_err(|e| e.with_context("failed to unarmor"))?;
    secretcrypt::decrypt(&passphrase, &ciphertext)
        .map_err(|e| e.with_context("failed to decrypt"))?;

    // Great, let's re-write it (atomically).
    let crypt_dir = crypt_path.parent().ok_or_else(|| {
        SaltyboxError::with_kind(
            ErrorCategory::User,
            ErrorKind::Io,
            "crypt_path has no parent directory",
        )
    })?;
    let mut temp_file = tempfile::Builder::new()
        .prefix(TEMPFILE_PREFIX)
        .suffix(TEMPFILE_SUFFIX)
        .tempfile_in(crypt_dir)
        .map_err(|e| {
            SaltyboxError::with_kind_and_source(
                ErrorCategory::Internal,
                ErrorKind::Io,
                "failed to create tempfile",
                e,
            )
        })?;
    let new_plaintext = fs::read(plain_path).map_err(|e| read_error(plain_path, e))?;
    let new_ciphertext = secretcrypt::encrypt(&passphrase, &new_plaintext)
        .map_err(|e| e.with_context("failed to encrypt"))?;
    let new_armored = varmor::wrap(&new_ciphertext);

    temp_file.write_all(new_armored.as_bytes()).map_err(|e| {
        SaltyboxError::with_kind_and_source(
            ErrorCategory::Internal,
            ErrorKind::Io,
            "failed to write to tempfile",
            e,
        )
    })?;
    // Flush and fsync() such that the rename later, if it succeeds, will
    // always point to a valid file.
    temp_file.flush().map_err(|e| {
        SaltyboxError::with_kind_and_source(
            ErrorCategory::Internal,
            ErrorKind::Io,
            "failed to flush tempfile",
            e,
        )
    })?;
    temp_file.as_file().sync_all().map_err(|e| {
        SaltyboxError::with_kind_and_source(
            ErrorCategory::Internal,
            ErrorKind::Io,
            "failed to sync file prior to rename",
            e,
        )
    })?;

    // Atomically rename temp file to target (persist with restrictive permissions)
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = temp_file
            .as_file()
            .metadata()
            .map_err(|e| {
                SaltyboxError::with_kind_and_source(
                    ErrorCategory::Internal,
                    ErrorKind::Io,
                    "failed to get tempfile metadata",
                    e,
                )
            })?
            .permissions();
        perms.set_mode(0o600);
        temp_file.as_file().set_permissions(perms).map_err(|e| {
            SaltyboxError::with_kind_and_source(
                ErrorCategory::Internal,
                ErrorKind::Io,
                "failed to set tempfile permissions",
                e,
            )
        })?;
    }
    temp_file.persist(crypt_path).map_err(|e| {
        let tempfile_path = e.file.path().display().to_string();
        SaltyboxError::with_kind_and_source(
            ErrorCategory::Internal,
            ErrorKind::Io,
            format!(
                "failed to rename to target file {}; tempfile may still exist at {} and may need manual removal",
                crypt_path.display(),
                tempfile_path
            ),
            e,
        )
    })?;
    Ok(())
}

/// Write file with secure permissions (0o600 on Unix)
fn write_file_secure(path: &Path, contents: &[u8]) -> Result<()> {
    let output_dir = path.parent().ok_or_else(|| {
        SaltyboxError::with_kind(
            ErrorCategory::User,
            ErrorKind::Io,
            "output path has no parent directory",
        )
    })?;
    let mut temp_file = tempfile::Builder::new()
        .prefix(TEMPFILE_PREFIX)
        .suffix(TEMPFILE_SUFFIX)
        .tempfile_in(output_dir)
        .map_err(|e| {
            SaltyboxError::with_kind_and_source(
                ErrorCategory::User,
                ErrorKind::Io,
                format!("failed to open {}", path.display()),
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
    Ok(())
}

fn read_error(path: &Path, err: io::Error) -> SaltyboxError {
    let category = if err.kind() == io::ErrorKind::NotFound {
        ErrorCategory::User
    } else {
        ErrorCategory::Internal
    };
    SaltyboxError::with_kind_and_source(
        category,
        ErrorKind::Io,
        format!("failed to read from {}", path.display()),
        err,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::ErrorKind;
    use crate::passphrase::ConstantPassphraseReader;
    use std::fs;
    use tempfile::TempDir;

    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let temp_dir = TempDir::new().unwrap();
        let plain_path = temp_dir.path().join("plain.txt");
        let crypt_path = temp_dir.path().join("crypt.txt.saltybox");
        let decrypted_path = temp_dir.path().join("decrypted.txt");

        let plaintext = b"Hello, saltybox!";
        fs::write(&plain_path, plaintext).unwrap();

        let mut reader = ConstantPassphraseReader::new(b"test password".to_vec());
        encrypt_file(&plain_path, &crypt_path, &mut reader).unwrap();
        assert!(crypt_path.exists());

        let mut reader = ConstantPassphraseReader::new(b"test password".to_vec());
        decrypt_file(&crypt_path, &decrypted_path, &mut reader).unwrap();
        let decrypted = fs::read(&decrypted_path).unwrap();
        assert_eq!(decrypted, plaintext);
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
        encrypt_file(&plain1_path, &crypt_path, &mut reader).unwrap();

        let plaintext2 = b"Updated content";
        fs::write(&plain2_path, plaintext2).unwrap();

        let mut reader = ConstantPassphraseReader::new(b"test password".to_vec());
        update_file(&plain2_path, &crypt_path, &mut reader).unwrap();

        let decrypted_path = temp_dir.path().join("decrypted.txt");
        let mut reader = ConstantPassphraseReader::new(b"test password".to_vec());
        decrypt_file(&crypt_path, &decrypted_path, &mut reader).unwrap();

        let decrypted = fs::read(&decrypted_path).unwrap();
        assert_eq!(decrypted, plaintext2);
    }

    #[test]
    fn test_update_with_wrong_passphrase_fails() {
        let temp_dir = TempDir::new().unwrap();
        let plain1_path = temp_dir.path().join("plain1.txt");
        let plain2_path = temp_dir.path().join("plain2.txt");
        let crypt_path = temp_dir.path().join("crypt.txt.saltybox");

        fs::write(&plain1_path, b"Initial").unwrap();
        let mut reader = ConstantPassphraseReader::new(b"correct password".to_vec());
        encrypt_file(&plain1_path, &crypt_path, &mut reader).unwrap();

        fs::write(&plain2_path, b"Updated").unwrap();
        let mut reader = ConstantPassphraseReader::new(b"wrong password".to_vec());
        let result = update_file(&plain2_path, &crypt_path, &mut reader);

        let err = result.expect_err("expected authentication failure");
        assert_eq!(err.kind, Some(ErrorKind::AuthenticationFailed));
    }

    #[test]
    #[cfg(unix)]
    fn test_file_permissions() {
        let temp_dir = TempDir::new().unwrap();
        let plain_path = temp_dir.path().join("plain.txt");
        let crypt_path = temp_dir.path().join("crypt.txt.saltybox");

        fs::write(&plain_path, b"test").unwrap();

        let mut reader = ConstantPassphraseReader::new(b"test".to_vec());
        encrypt_file(&plain_path, &crypt_path, &mut reader).unwrap();

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
        encrypt_file(&plain_path, &crypt_path, &mut reader).unwrap();

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
        encrypt_file(&plain_path, &crypt_path, &mut reader).unwrap();

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
    fn test_decrypt_wrong_passphrase() {
        let temp_dir = TempDir::new().unwrap();
        let plain_path = temp_dir.path().join("plain.txt");
        let crypt_path = temp_dir.path().join("crypt.txt.saltybox");
        let decrypted_path = temp_dir.path().join("decrypted.txt");

        fs::write(&plain_path, b"secret").unwrap();

        let mut reader = ConstantPassphraseReader::new(b"correct".to_vec());
        encrypt_file(&plain_path, &crypt_path, &mut reader).unwrap();

        let mut reader = ConstantPassphraseReader::new(b"wrong".to_vec());
        let result = decrypt_file(&crypt_path, &decrypted_path, &mut reader);

        assert!(result.is_err());
    }

    #[test]
    fn test_empty_file() {
        let temp_dir = TempDir::new().unwrap();
        let plain_path = temp_dir.path().join("empty.txt");
        let crypt_path = temp_dir.path().join("empty.txt.saltybox");
        let decrypted_path = temp_dir.path().join("decrypted.txt");

        fs::write(&plain_path, b"").unwrap();

        let mut reader = ConstantPassphraseReader::new(b"test".to_vec());
        encrypt_file(&plain_path, &crypt_path, &mut reader).unwrap();

        let mut reader = ConstantPassphraseReader::new(b"test".to_vec());
        decrypt_file(&crypt_path, &decrypted_path, &mut reader).unwrap();

        let decrypted = fs::read(&decrypted_path).unwrap();
        assert_eq!(decrypted, b"");
    }
}
