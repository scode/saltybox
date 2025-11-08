//! Core encryption/decryption using scrypt + XSalsa20Poly1305

use anyhow::Result;

/// Encrypt plaintext with a passphrase
///
/// Returns the binary format: salt(8) + nonce(24) + length(8) + sealedbox(variable)
pub fn encrypt(_passphrase: &str, _plaintext: &[u8]) -> Result<Vec<u8>> {
    // TODO: Step 2
    todo!("encrypt not yet implemented")
}

/// Decrypt ciphertext with a passphrase
pub fn decrypt(_passphrase: &str, _ciphertext: &[u8]) -> Result<Vec<u8>> {
    // TODO: Step 2
    todo!("decrypt not yet implemented")
}

#[cfg(test)]
mod tests {
    #[test]
    fn test_placeholder() {
        // Placeholder test.
    }
}
