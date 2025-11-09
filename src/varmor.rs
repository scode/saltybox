//! Versioned armoring for binary data
//!
//! Provides base64url encoding with a version prefix for encrypted data.
//! The armored format is:
//! - Free of whitespace (including newlines)
//! - Safe to embed in URLs
//! - Safe to pass unescaped in a POSIX shell

use anyhow::{Result, bail};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};

/// Magic prefix for all saltybox versions
const MAGIC_PREFIX: &str = "saltybox";

/// Version 1 magic marker
const V1_MAGIC: &str = "saltybox1:";

/// Wrap bytes in armor, returning the armored string
///
/// Format: saltybox1:{base64url-no-padding}
pub fn wrap(body: &[u8]) -> String {
    let encoded = URL_SAFE_NO_PAD.encode(body);
    format!("{}{}", V1_MAGIC, encoded)
}

/// Unwrap an armored string, returning the original bytes
pub fn unwrap(armored: &str) -> Result<Vec<u8>> {
    if armored.len() < V1_MAGIC.len() {
        bail!("input size smaller than magic marker; likely truncated");
    }

    if let Some(encoded) = armored.strip_prefix(V1_MAGIC) {
        let body = URL_SAFE_NO_PAD
            .decode(encoded)
            .map_err(|e| anyhow::anyhow!("base64 decoding failed: {}", e))?;
        Ok(body)
    } else if armored.starts_with(MAGIC_PREFIX) {
        bail!("input claims to be saltybox, but not a version we support");
    } else {
        bail!("input unrecognized as saltybox data");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_empty_bytes() {
        let bytes = b"";
        let armored = wrap(bytes);
        let unwrapped = unwrap(&armored).unwrap();
        assert_eq!(bytes, &unwrapped[..]);
    }

    #[test]
    fn test_simple_string() {
        let bytes = b"test";
        let armored = wrap(bytes);
        let unwrapped = unwrap(&armored).unwrap();
        assert_eq!(bytes, &unwrapped[..]);
    }

    #[test]
    fn test_large_random_data() {
        let bytes = vec![0x42u8; 100_000];
        let armored = wrap(&bytes);
        let unwrapped = unwrap(&armored).unwrap();
        assert_eq!(bytes, unwrapped);
    }

    #[test]
    fn test_all_byte_values() {
        let bytes: Vec<u8> = (0..=255).collect();
        let armored = wrap(&bytes);

        // Test for exact output - this also matches the exact string used in
        // the previous Go implementation.
        assert_eq!(
            armored,
            "saltybox1:AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8gISIjJCUmJygpKissLS4vMDEyMzQ1Njc4OTo7PD0-P0BBQkNERUZHSElKS0xNTk9QUVJTVFVWV1hZWltcXV5fYGFiY2RlZmdoaWprbG1ub3BxcnN0dXZ3eHl6e3x9fn-AgYKDhIWGh4iJiouMjY6PkJGSk5SVlpeYmZqbnJ2en6ChoqOkpaanqKmqq6ytrq-wsbKztLW2t7i5uru8vb6_wMHCw8TFxsfIycrLzM3Oz9DR0tPU1dbX2Nna29zd3t_g4eLj5OXm5-jp6uvs7e7v8PHy8_T19vf4-fr7_P3-_w"
        );

        let unwrapped = unwrap(&armored).unwrap();
        assert_eq!(bytes, unwrapped);
    }

    #[test]
    fn test_truncated_input() {
        let result = unwrap("");
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("input size smaller than magic marker; likely truncated")
        );
    }

    #[test]
    fn test_wrong_version() {
        let result = unwrap("saltybox999999:...");
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err().to_string(),
            "input claims to be saltybox, but not a version we support"
        );
    }

    #[test]
    fn test_not_saltybox() {
        let result = unwrap("something not looking like saltybox data");
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err().to_string(),
            "input unrecognized as saltybox data"
        );
    }

    #[test]
    fn test_bad_base64() {
        let result = unwrap("saltybox1:bad$$");
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("base64 decoding failed")
        );
    }

    #[test]
    fn test_no_whitespace() {
        let bytes = b"test data with spaces";
        let armored = wrap(bytes);

        assert!(!armored.contains(' '));
        assert!(!armored.contains('\n'));
        assert!(!armored.contains('\t'));
    }

    #[test]
    fn test_url_safe() {
        let bytes = vec![0xFFu8; 100]; // Bytes that might encode to + or / in standard base64
        let armored = wrap(&bytes);

        assert!(!armored.contains('+'));
        assert!(!armored.contains('/'));

        // Verify no padding
        assert!(!armored.contains('='));
    }
}
