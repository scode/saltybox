//! File encryption/decryption operations
//!
//! This module provides high-level file operations for encrypting, decrypting,
//! and updating files using the saltybox format.

use anyhow::{Context, Result};
use std::fs;
use std::io::Write;
use std::path::Path;

use crate::passphrase::PassphraseReader;
use crate::secretcrypt;
use crate::varmor;

/// Encrypt a file with a passphrase
///
/// Reads plaintext from `input_path`, encrypts it using a passphrase from
/// `passphrase_reader`, and writes the armored ciphertext to `output_path`.
///
/// The output file is created with mode 0o600 (read/write for owner only) on Unix systems.
pub fn encrypt_file(
    input_path: &Path,
    output_path: &Path,
    passphrase_reader: &mut dyn PassphraseReader,
) -> Result<()> {
    let plaintext = fs::read(input_path)
        .with_context(|| format!("failed to read from {}", input_path.display()))?;
    let passphrase = passphrase_reader.read_passphrase()?;
    let ciphertext =
        secretcrypt::encrypt(passphrase.as_bytes(), &plaintext).context("encryption failed")?;
    let armored = varmor::wrap(&ciphertext);
    write_file_secure(output_path, armored.as_bytes())
        .with_context(|| format!("failed to write to {}", output_path.display()))?;

    Ok(())
}

/// Decrypt a file with a passphrase
///
/// Reads armored ciphertext from `input_path`, decrypts it using a passphrase from
/// `passphrase_reader`, and writes the plaintext to `output_path`.
///
/// The output file is created with mode 0o600 (read/write for owner only) on Unix systems.
pub fn decrypt_file(
    input_path: &Path,
    output_path: &Path,
    passphrase_reader: &mut dyn PassphraseReader,
) -> Result<()> {
    let armored_bytes = fs::read(input_path)
        .with_context(|| format!("failed to read from {}", input_path.display()))?;
    let armored = String::from_utf8(armored_bytes).context("input file is not valid UTF-8")?;
    let passphrase = passphrase_reader.read_passphrase()?;
    let ciphertext = varmor::unwrap(&armored).context("failed to unarmor")?;
    let plaintext =
        secretcrypt::decrypt(passphrase.as_bytes(), &ciphertext).context("failed to decrypt")?;
    write_file_secure(output_path, &plaintext)
        .with_context(|| format!("failed to write to {}", output_path.display()))?;
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
    let armored_bytes = fs::read(crypt_path)
        .with_context(|| format!("failed to read from {}", crypt_path.display()))?;
    let armored = String::from_utf8(armored_bytes).context("encrypted file is not valid UTF-8")?;
    let passphrase = passphrase_reader.read_passphrase()?;

    // Validate passphrase by decrypting existing file (discard plaintext)
    let ciphertext = varmor::unwrap(&armored).context("failed to unarmor")?;
    secretcrypt::decrypt(passphrase.as_bytes(), &ciphertext).context("failed to decrypt")?;

    // Great, let's re-write it (atomically).
    let crypt_dir = crypt_path
        .parent()
        .context("crypt_path has no parent directory")?;
    let mut temp_file =
        tempfile::NamedTempFile::new_in(crypt_dir).context("failed to create tempfile")?;
    let new_plaintext = fs::read(plain_path)
        .with_context(|| format!("failed to read from {}", plain_path.display()))?;
    let new_ciphertext =
        secretcrypt::encrypt(passphrase.as_bytes(), &new_plaintext).context("failed to encrypt")?;
    let new_armored = varmor::wrap(&new_ciphertext);

    temp_file
        .write_all(new_armored.as_bytes())
        .context("failed to write to tempfile")?;
    // Flush and fsync() such that the rename later, if it succeeds, will
    // always point to a valid file.
    temp_file.flush().context("failed to flush tempfile")?;
    temp_file
        .as_file()
        .sync_all()
        .context("failed to sync file prior to rename")?;

    // Atomically rename temp file to target (persist with restrictive permissions)
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = temp_file
            .as_file()
            .metadata()
            .context("failed to get tempfile metadata")?
            .permissions();
        perms.set_mode(0o600);
        temp_file
            .as_file()
            .set_permissions(perms)
            .context("failed to set tempfile permissions")?;
    }
    temp_file
        .persist(crypt_path)
        .with_context(|| format!("failed to rename to target file {}", crypt_path.display()))?;
    Ok(())
}

/// Write file with secure permissions (0o600 on Unix)
fn write_file_secure(path: &Path, contents: &[u8]) -> Result<()> {
    #[cfg(unix)]
    {
        use std::fs::OpenOptions;
        use std::os::unix::fs::OpenOptionsExt;

        let mut file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(path)?;

        file.write_all(contents)?;
        Ok(())
    }

    #[cfg(not(unix))]
    {
        fs::write(path, contents)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
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

        let mut reader = ConstantPassphraseReader::new("test password".to_string());
        encrypt_file(&plain_path, &crypt_path, &mut reader).unwrap();
        assert!(crypt_path.exists());

        let mut reader = ConstantPassphraseReader::new("test password".to_string());
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

        let mut reader = ConstantPassphraseReader::new("test password".to_string());
        encrypt_file(&plain1_path, &crypt_path, &mut reader).unwrap();

        let plaintext2 = b"Updated content";
        fs::write(&plain2_path, plaintext2).unwrap();

        let mut reader = ConstantPassphraseReader::new("test password".to_string());
        update_file(&plain2_path, &crypt_path, &mut reader).unwrap();

        let decrypted_path = temp_dir.path().join("decrypted.txt");
        let mut reader = ConstantPassphraseReader::new("test password".to_string());
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
        let mut reader = ConstantPassphraseReader::new("correct password".to_string());
        encrypt_file(&plain1_path, &crypt_path, &mut reader).unwrap();

        fs::write(&plain2_path, b"Updated").unwrap();
        let mut reader = ConstantPassphraseReader::new("wrong password".to_string());
        let result = update_file(&plain2_path, &crypt_path, &mut reader);

        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("failed to decrypt")
        );
    }

    #[test]
    #[cfg(unix)]
    fn test_file_permissions() {
        let temp_dir = TempDir::new().unwrap();
        let plain_path = temp_dir.path().join("plain.txt");
        let crypt_path = temp_dir.path().join("crypt.txt.saltybox");

        fs::write(&plain_path, b"test").unwrap();

        let mut reader = ConstantPassphraseReader::new("test".to_string());
        encrypt_file(&plain_path, &crypt_path, &mut reader).unwrap();

        let metadata = fs::metadata(&crypt_path).unwrap();
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

        let mut reader = ConstantPassphraseReader::new("correct".to_string());
        encrypt_file(&plain_path, &crypt_path, &mut reader).unwrap();

        let mut reader = ConstantPassphraseReader::new("wrong".to_string());
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

        let mut reader = ConstantPassphraseReader::new("test".to_string());
        encrypt_file(&plain_path, &crypt_path, &mut reader).unwrap();

        let mut reader = ConstantPassphraseReader::new("test".to_string());
        decrypt_file(&crypt_path, &decrypted_path, &mut reader).unwrap();

        let decrypted = fs::read(&decrypted_path).unwrap();
        assert_eq!(decrypted, b"");
    }
}
