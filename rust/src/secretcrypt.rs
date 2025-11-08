//! Encryption/decryption using scrypt + XSalsa20Poly1305
//!
//! This module implements passphrase-based encryption using:
//! - scrypt for key derivation from passphrase
//! - NaCl secretbox (XSalsa20Poly1305) for authenticated encryption
//!
//! The binary format is:
//! - salt: 8 bytes
//! - nonce: 24 bytes
//! - length: 8 bytes (big-endian signed int64)
//! - sealed box: variable length (includes 16-byte Poly1305 MAC)

use anyhow::{Context, Result, bail};
use crypto_secretbox::aead::{Aead, KeyInit};
use crypto_secretbox::{Nonce, XSalsa20Poly1305};
use rand::RngCore;
use rand::rngs::OsRng;
use scrypt::{Params, scrypt};
use std::mem::{size_of, size_of_val};

/// Length of salt in bytes
const SALT_LEN: usize = 8;

/// Length of nonce in bytes
const NONCE_LEN: usize = 24;

/// Length of derived key in bytes
const KEY_LEN: usize = 32;

/// scrypt N parameter (CPU/memory cost)
const SCRYPT_N: u32 = 32768;

/// scrypt r parameter (block size)
const SCRYPT_R: u32 = 8;

/// scrypt p parameter (parallelization)
const SCRYPT_P: u32 = 1;

/// Derive a 32-byte key from a passphrase and salt using scrypt
fn derive_key(passphrase: &[u8], salt: &[u8; SALT_LEN]) -> Result<[u8; KEY_LEN]> {
    let params = Params::new(
        (SCRYPT_N as f64).log2() as u8, // log_n
        SCRYPT_R,
        SCRYPT_P,
        KEY_LEN,
    )
    .context("failed to create scrypt params")?;

    let mut key = [0u8; KEY_LEN];
    scrypt(passphrase, salt, &params, &mut key).context("scrypt key derivation failed")?;

    Ok(key)
}

/// Encrypt plaintext with a passphrase using random salt and nonce
///
/// Returns the binary format: salt(8) + nonce(24) + length(8) + sealedbox(variable)
pub fn encrypt(passphrase: &[u8], plaintext: &[u8]) -> Result<Vec<u8>> {
    let mut salt = [0u8; SALT_LEN];
    OsRng.fill_bytes(&mut salt);

    let mut nonce = [0u8; NONCE_LEN];
    OsRng.fill_bytes(&mut nonce);

    encrypt_deterministic(passphrase, plaintext, &salt, &nonce)
}

/// Encrypt plaintext with a passphrase using provided salt and nonce
///
/// This function is ONLY for testing purposes to generate deterministic output.
/// NEVER use this in production - always use `encrypt()` which generates random salt/nonce.
pub fn encrypt_deterministic(
    passphrase: &[u8],
    plaintext: &[u8],
    salt: &[u8; SALT_LEN],
    nonce: &[u8; NONCE_LEN],
) -> Result<Vec<u8>> {
    let key = derive_key(passphrase, salt)?;

    let cipher = XSalsa20Poly1305::new(&key.into());

    let nonce_obj = Nonce::from(*nonce);
    let sealed_box = cipher
        .encrypt(&nonce_obj, plaintext)
        .map_err(|e| anyhow::anyhow!("encryption failed: {}", e))?;

    let sealed_box_len = sealed_box.len() as i64;
    let mut output =
        Vec::with_capacity(SALT_LEN + NONCE_LEN + size_of_val(&sealed_box_len) + sealed_box.len());
    output.extend_from_slice(salt);
    output.extend_from_slice(nonce);
    output.extend_from_slice(&sealed_box_len.to_be_bytes()); // big-endian i64
    output.extend_from_slice(&sealed_box);

    Ok(output)
}

/// Decrypt ciphertext with a passphrase
pub fn decrypt(passphrase: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>> {
    let mut pos = 0;

    if ciphertext.len() < pos + SALT_LEN {
        bail!("input likely truncated while reading salt");
    }
    let salt: [u8; SALT_LEN] = ciphertext[pos..pos + SALT_LEN]
        .try_into()
        .context("failed to read salt")?;
    pos += SALT_LEN;

    if ciphertext.len() < pos + NONCE_LEN {
        bail!("input likely truncated while reading nonce");
    }
    let nonce: [u8; NONCE_LEN] = ciphertext[pos..pos + NONCE_LEN]
        .try_into()
        .context("failed to read nonce")?;
    pos += NONCE_LEN;

    if ciphertext.len() < pos + size_of::<i64>() {
        bail!("input likely truncated while reading sealed box");
    }
    let length_bytes: [u8; 8] = ciphertext[pos..pos + size_of::<i64>()]
        .try_into()
        .context("failed to read length")?;
    let sealed_box_len = i64::from_be_bytes(length_bytes);
    pos += size_of::<i64>();

    if sealed_box_len < 0 {
        bail!("negative sealed box length (when interpreted as a big-endian i64)");
    }

    // Check if length exceeds platform's maximum isize. *Valid* input
    // can fail this check if the platforms' isize is small.
    if sealed_box_len > isize::MAX as i64 {
        bail!("sealed box length exceeds this system's max isize");
    }

    let sealed_box_len = sealed_box_len as usize;

    if sealed_box_len > ciphertext.len() {
        bail!("truncated or corrupt input; claimed length greater than available input");
    }

    if ciphertext.len() < pos + sealed_box_len {
        bail!("truncated or corrupt input (while reading sealed box)");
    }
    let sealed_box = &ciphertext[pos..pos + sealed_box_len];
    pos += sealed_box_len;

    if pos < ciphertext.len() {
        bail!("invalid input: unexpected data after sealed box");
    }

    let key = derive_key(passphrase, &salt)?;
    let cipher = XSalsa20Poly1305::new(&key.into());
    let nonce_obj = Nonce::from(nonce);
    let plaintext = cipher
        .decrypt(&nonce_obj, sealed_box)
        .map_err(|_| anyhow::anyhow!("corrupt input, tampered-with data, or bad passphrase"))?;

    Ok(plaintext)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_empty_plaintext() {
        let passphrase = "test";
        let plaintext = b"";

        let ciphertext = encrypt(passphrase.as_bytes(), plaintext).unwrap();
        let decrypted = decrypt(passphrase.as_bytes(), &ciphertext).unwrap();

        assert_eq!(plaintext, &decrypted[..]);
    }

    #[test]
    fn test_small_plaintext() {
        let passphrase = "test";
        let plaintext = b"hello";

        let ciphertext = encrypt(passphrase.as_bytes(), plaintext).unwrap();
        let decrypted = decrypt(passphrase.as_bytes(), &ciphertext).unwrap();

        assert_eq!(plaintext, &decrypted[..]);
    }

    #[test]
    fn test_deterministic_encryption() {
        let passphrase = "test";
        let plaintext = b"hello world";
        let salt = [1u8; SALT_LEN];
        let nonce = [2u8; NONCE_LEN];

        let ct1 = encrypt_deterministic(passphrase.as_bytes(), plaintext, &salt, &nonce).unwrap();
        let ct2 = encrypt_deterministic(passphrase.as_bytes(), plaintext, &salt, &nonce).unwrap();

        // Same salt/nonce produces identical ciphertext
        assert_eq!(ct1, ct2);

        // Both decrypt to same plaintext
        let pt1 = decrypt(passphrase.as_bytes(), &ct1).unwrap();
        let pt2 = decrypt(passphrase.as_bytes(), &ct2).unwrap();
        assert_eq!(plaintext, &pt1[..]);
        assert_eq!(plaintext, &pt2[..]);
    }

    #[test]
    fn test_different_nonce_different_ciphertext() {
        let passphrase = "test";
        let plaintext = b"hello world";
        let salt = [1u8; SALT_LEN];
        let nonce1 = [2u8; NONCE_LEN];
        let nonce2 = [3u8; NONCE_LEN];

        let ct1 = encrypt_deterministic(passphrase.as_bytes(), plaintext, &salt, &nonce1).unwrap();
        let ct2 = encrypt_deterministic(passphrase.as_bytes(), plaintext, &salt, &nonce2).unwrap();

        // Different nonce produces different ciphertext
        assert_ne!(ct1, ct2);

        // Both decrypt to same plaintext
        let pt1 = decrypt(passphrase.as_bytes(), &ct1).unwrap();
        let pt2 = decrypt(passphrase.as_bytes(), &ct2).unwrap();
        assert_eq!(plaintext, &pt1[..]);
        assert_eq!(plaintext, &pt2[..]);
    }

    #[test]
    fn test_wrong_passphrase() {
        let plaintext = b"secret data";

        let ciphertext = encrypt(b"correct", plaintext).unwrap();
        let result = decrypt(b"wrong", &ciphertext);

        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("corrupt input, tampered-with data, or bad passphrase")
        );
    }

    #[test]
    fn test_truncated_salt() {
        let ciphertext = vec![1, 2, 3]; // Less than SALT_LEN
        let result = decrypt(b"test", &ciphertext);

        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("input likely truncated while reading salt")
        );
    }

    #[test]
    fn test_truncated_nonce() {
        let ciphertext = vec![0u8; SALT_LEN + 3]; // Incomplete nonce
        let result = decrypt(b"test", &ciphertext);

        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("input likely truncated while reading nonce")
        );
    }

    #[test]
    fn test_truncated_length() {
        let ciphertext = vec![0u8; SALT_LEN + NONCE_LEN + 3]; // Incomplete length
        let result = decrypt(b"test", &ciphertext);

        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("input likely truncated while reading sealed box")
        );
    }

    #[test]
    fn test_negative_length() {
        let mut ciphertext = vec![0u8; SALT_LEN + NONCE_LEN + 8];
        // Write negative length
        let negative: i64 = -1;
        ciphertext[SALT_LEN + NONCE_LEN..SALT_LEN + NONCE_LEN + 8]
            .copy_from_slice(&negative.to_be_bytes());

        let result = decrypt(b"test", &ciphertext);

        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("negative sealed box length")
        );
    }

    #[test]
    fn test_length_exceeds_available() {
        let passphrase = b"test";
        let plaintext = b"hello";

        let mut ciphertext = encrypt(passphrase, plaintext).unwrap();

        // Modify length to be larger than actual data
        let huge_length: i64 = 1000000;
        ciphertext[SALT_LEN + NONCE_LEN..SALT_LEN + NONCE_LEN + 8]
            .copy_from_slice(&huge_length.to_be_bytes());

        let result = decrypt(passphrase, &ciphertext);

        assert!(result.is_err());
        assert!(
            result.unwrap_err().to_string().contains(
                "truncated or corrupt input; claimed length greater than available input"
            )
        );
    }

    #[test]
    fn test_trailing_data() {
        let passphrase = b"test";
        let plaintext = b"hello";

        let mut ciphertext = encrypt(passphrase, plaintext).unwrap();
        // Add trailing junk
        ciphertext.push(0xFF);

        let result = decrypt(passphrase, &ciphertext);

        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("invalid input: unexpected data after sealed box")
        );
    }

    #[test]
    fn test_all_zero_bytes() {
        let passphrase = b"test";
        let plaintext = vec![0u8; 100];

        let ciphertext = encrypt(passphrase, &plaintext).unwrap();
        let decrypted = decrypt(passphrase, &ciphertext).unwrap();

        assert_eq!(plaintext, decrypted);
    }

    #[test]
    fn test_all_ff_bytes() {
        let passphrase = b"test";
        let plaintext = vec![0xFFu8; 100];

        let ciphertext = encrypt(passphrase, &plaintext).unwrap();
        let decrypted = decrypt(passphrase, &ciphertext).unwrap();

        assert_eq!(plaintext, decrypted);
    }

    #[test]
    fn test_all_byte_values() {
        let passphrase = b"test";
        let plaintext: Vec<u8> = (0..=255).collect();

        let ciphertext = encrypt(passphrase, &plaintext).unwrap();
        let decrypted = decrypt(passphrase, &ciphertext).unwrap();

        assert_eq!(plaintext, decrypted);
    }

    #[test]
    fn test_large_plaintext() {
        let passphrase = b"test";
        let plaintext = vec![0x42u8; 128 * 1024]; // 128KB

        let ciphertext = encrypt(passphrase, &plaintext).unwrap();
        let decrypted = decrypt(passphrase, &ciphertext).unwrap();

        assert_eq!(plaintext, decrypted);
    }

    #[test]
    fn test_cross_implementation_compatibility() {
        // This test uses the exact same parameters as the Go implementation's
        // TestCrossImplementationCompatibility to verify byte-for-byte compatibility
        let passphrase = b"test";
        let plaintext = b"test payload";

        // Use same fixed salt and nonce as Go test
        let salt = [0x42u8; SALT_LEN];
        let nonce = [0x24u8; NONCE_LEN];

        let ciphertext = encrypt_deterministic(passphrase, plaintext, &salt, &nonce).unwrap();

        // Expected output - this exact byte sequence is produced by the Go implementation.
        // See corresponding unit test in the Go version.
        #[rustfmt::skip]
        let expected: Vec<u8> = vec![
            0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42,
            0x24, 0x24, 0x24, 0x24, 0x24, 0x24, 0x24, 0x24,
            0x24, 0x24, 0x24, 0x24, 0x24, 0x24, 0x24, 0x24,
            0x24, 0x24, 0x24, 0x24, 0x24, 0x24, 0x24, 0x24,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x1c,
            0x44, 0x87, 0xfe, 0xcd, 0x6f, 0xcf, 0x10, 0x75,
            0x7b, 0x4c, 0xb9, 0xc6, 0x59, 0xda, 0x83, 0x61,
            0x28, 0xfc, 0xf4, 0x30, 0x39, 0x85, 0x4a, 0x66,
            0xcf, 0xb5, 0xcf, 0xd4,
        ];

        assert_eq!(
            ciphertext, expected,
            "Rust ciphertext should match Go implementation exactly"
        );

        let decrypted = decrypt(passphrase, &ciphertext).unwrap();
        assert_eq!(plaintext, &decrypted[..]);
    }
}
