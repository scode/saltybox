use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::Path;

use crate::preader::PassphraseReader;
use crate::secretcrypt;
use crate::varmor;

fn encrypt_bytes(passphrase: &str, plaintext: &[u8]) -> anyhow::Result<String> {
    let cipher_bytes = secretcrypt::encrypt(passphrase, plaintext)?;
    let varmored = varmor::wrap(&cipher_bytes);
    Ok(varmored)
}

pub fn encrypt(inpath: &Path, outpath: &Path, mut pr: impl PassphraseReader) -> anyhow::Result<()> {
    let plaintext = fs::read(inpath)
        .map_err(|e| anyhow::anyhow!("failed to read from {}: {}", inpath.display(), e))?;
    let passphrase = pr.read_passphrase()?;
    let encrypted = encrypt_bytes(&passphrase, &plaintext)?;

    // Write with 0600 permissions best-effort
    let mut f = OpenOptions::new().create(true).truncate(true).write(true).open(outpath)
        .map_err(|e| anyhow::anyhow!("failed to write to {}: {}", outpath.display(), e))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(outpath, fs::Permissions::from_mode(0o600));
    }
    f.write_all(encrypted.as_bytes())
        .map_err(|e| anyhow::anyhow!("failed to write to {}: {}", outpath.display(), e))?;
    Ok(())
}

fn decrypt_string(passphrase: &str, encrypted_string: &str) -> anyhow::Result<Vec<u8>> {
    let cipher_bytes = varmor::unwrap(encrypted_string)
        .map_err(|e| anyhow::anyhow!("failed to unarmor: {}", e))?;
    let plaintext = secretcrypt::decrypt(passphrase, &cipher_bytes)
        .map_err(|e| anyhow::anyhow!("failed to decrypt: {}", e))?;
    Ok(plaintext)
}

pub fn decrypt(inpath: &Path, outpath: &Path, mut pr: impl PassphraseReader) -> anyhow::Result<()> {
    let varmored_bytes = fs::read(inpath)
        .map_err(|e| anyhow::anyhow!("failed to read from {}: {}", inpath.display(), e))?;
    let passphrase = pr.read_passphrase()?;
    let plaintext = decrypt_string(&passphrase, &String::from_utf8_lossy(&varmored_bytes))?;
    let mut f = OpenOptions::new().create(true).truncate(true).write(true).open(outpath)
        .map_err(|e| anyhow::anyhow!("failed to write to {}: {}", outpath.display(), e))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(outpath, fs::Permissions::from_mode(0o600));
    }
    f.write_all(&plaintext)
        .map_err(|e| anyhow::anyhow!("failed to write to {}: {}", outpath.display(), e))?;
    Ok(())
}

pub fn update(plainfile: &Path, cryptfile: &Path, pr: impl PassphraseReader) -> anyhow::Result<()> {
    // Validate passphrase by decrypting existing file first
    let varmored_bytes = fs::read(cryptfile)
        .map_err(|e| anyhow::anyhow!("failed to read from {}: {}", cryptfile.display(), e))?;
    let mut caching = crate::preader::CachingPassphraseReader::new(pr);
    let passphrase = caching.read_passphrase()?;
    let _ = decrypt_string(&passphrase, &String::from_utf8_lossy(&varmored_bytes))
        .map_err(|e| anyhow::anyhow!("failed to decrypt: {}", e))?;

    // Atomic replace via tempfile, fsync and rename
    let crypt_dir = cryptfile.parent().unwrap_or_else(|| Path::new("."));
    let tmp = tempfile::Builder::new()
        .prefix("saltybox-update-tmp")
        .tempfile_in(crypt_dir)?;

    // Write encrypted contents to tmp path using Encrypt
    let tmp_path = tmp.path().to_path_buf();
    // Ensure file exists with correct perms before writing
    {
        let _f = File::create(&tmp_path)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = fs::set_permissions(&tmp_path, fs::Permissions::from_mode(0o600));
        }
    }

    encrypt(plainfile, &tmp_path, caching)?;

    // Re-open to ensure we fsync the correct file
    let reopened = OpenOptions::new().read(true).write(true).open(&tmp_path)?;
    reopened.sync_all()?;

    // Persist moves it into place atomically
    tmp.persist(cryptfile)?;
    Ok(())
}

