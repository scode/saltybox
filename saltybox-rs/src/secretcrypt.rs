use std::io::Cursor;

use rand::RngCore;
use scrypt::Params as ScryptParams;
use xsalsa20poly1305::aead::{Aead, KeyInit};
use xsalsa20poly1305::{Key, Nonce, XSalsa20Poly1305};

const SALT_LEN: usize = 8;
const SECRETBOX_NONCE_LEN: usize = 24;
const KEY_LEN: usize = 32;

// scrypt parameters matching the Go implementation
const SCRYPT_N: u32 = 32768; // 2^15
const SCRYPT_R: u32 = 8;
const SCRYPT_P: u32 = 1;

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("random generation failed: {0}")]
    Rand(String),
    #[error("scrypt key derivation failed: {0}")]
    Scrypt(String),
    #[error("input likely truncated while reading salt: {0}")]
    TruncatedSalt(String),
    #[error("input likely truncated while reading nonce: {0}")]
    TruncatedNonce(String),
    #[error("input likely truncated while reading sealed box: {0}")]
    TruncatedSealedBox(String),
    #[error("negative sealed box length")]
    NegativeLength,
    #[error("sealed box length exceeds max int")]
    LengthExceedsMaxInt,
    #[error("truncated or corrupt input; claimed length greater than available input")]
    ClaimedTooLong,
    #[error("truncated or corrupt input (while reading sealed box)")]
    TruncatedWhileReadingSealed,
    #[error("invalid input: unexpected data after sealed box")]
    TrailingData,
    #[error("corrupt input, tampered-with data, or bad passphrase")]
    DecryptFailed,
}

fn derive_key(passphrase: &str, salt: &[u8; SALT_LEN]) -> Result<Key, Error> {
    // Use the scrypt crate directly to derive raw bytes. The password-hash API is not needed.
    // scrypt crate expects log_n (base 2), r, p
    let log_n = 15; // since N = 2^15 = 32768
    let params = ScryptParams::new(log_n, SCRYPT_R, SCRYPT_P, KEY_LEN)
        .map_err(|e| Error::Scrypt(e.to_string()))?;

    let mut derived = [0u8; KEY_LEN];
    scrypt::scrypt(passphrase.as_bytes(), salt, &params, &mut derived)
        .map_err(|e| Error::Scrypt(e.to_string()))?;

    Ok(Key::from_slice(&derived).to_owned())
}

pub fn encrypt(passphrase: &str, plaintext: &[u8]) -> Result<Vec<u8>, Error> {
    let mut salt = [0u8; SALT_LEN];
    rand::thread_rng().try_fill_bytes(&mut salt).map_err(|e| Error::Rand(e.to_string()))?;

    let key = derive_key(passphrase, &salt)?;
    let cipher = XSalsa20Poly1305::new(&key);

    let mut nonce_bytes = [0u8; SECRETBOX_NONCE_LEN];
    rand::thread_rng().try_fill_bytes(&mut nonce_bytes).map_err(|e| Error::Rand(e.to_string()))?;
    let nonce = Nonce::from_slice(&nonce_bytes);

    let sealed_box = cipher
        .encrypt(nonce, plaintext)
        .map_err(|_| Error::DecryptFailed)?; // encryption failure is unlikely; reuse error type conservatively

    // Build output: salt | nonce | int64(len) big-endian | sealed_box
    let mut out = Vec::with_capacity(SALT_LEN + SECRETBOX_NONCE_LEN + 8 + sealed_box.len());
    out.extend_from_slice(&salt);
    out.extend_from_slice(&nonce_bytes);
    let len_i64: i64 = sealed_box.len() as i64;
    out.extend_from_slice(&len_i64.to_be_bytes());
    out.extend_from_slice(&sealed_box);
    Ok(out)
}

pub fn decrypt(passphrase: &str, crypttext: &[u8]) -> Result<Vec<u8>, Error> {
    let mut cursor = Cursor::new(crypttext);

    let mut salt = [0u8; SALT_LEN];
    if std::io::Read::read_exact(&mut cursor, &mut salt).is_err() {
        return Err(Error::TruncatedSalt("read_exact failed".into()));
    }

    let mut nonce_bytes = [0u8; SECRETBOX_NONCE_LEN];
    if std::io::Read::read_exact(&mut cursor, &mut nonce_bytes).is_err() {
        return Err(Error::TruncatedNonce("read_exact failed".into()));
    }

    let mut len_bytes = [0u8; 8];
    if std::io::Read::read_exact(&mut cursor, &mut len_bytes).is_err() {
        return Err(Error::TruncatedSealedBox("read_exact failed".into()));
    }
    let sealed_len = i64::from_be_bytes(len_bytes);
    if sealed_len < 0 {
        return Err(Error::NegativeLength);
    }
    let max_int = (usize::MAX >> 1) as i64;
    if sealed_len > max_int {
        return Err(Error::LengthExceedsMaxInt);
    }
    if sealed_len as usize > crypttext.len() {
        return Err(Error::ClaimedTooLong);
    }

    let mut sealed_box = vec![0u8; sealed_len as usize];
    if std::io::Read::read_exact(&mut cursor, &mut sealed_box).is_err() {
        return Err(Error::TruncatedWhileReadingSealed);
    }

    // Verify no trailing data remains
    if (crypttext.len() as u64) > cursor.position() {
        return Err(Error::TrailingData);
    }

    let key = derive_key(passphrase, &salt)?;
    let cipher = XSalsa20Poly1305::new(&key);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let plaintext = cipher
        .decrypt(nonce, sealed_box.as_ref())
        .map_err(|_| Error::DecryptFailed)?;

    Ok(plaintext)
}

