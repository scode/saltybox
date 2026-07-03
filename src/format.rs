//! Format-engine dispatch across saltybox on-disk format versions.
//!
//! saltybox needs multiple format versions to coexist: files written years ago
//! must keep decrypting while newly written files can use newer cryptography.
//! This module is the seam that makes that possible. Each on-disk format is a
//! [`FormatEngine`] pairing an armor magic with the cryptography behind it;
//! the read side selects an engine by matching the magic at the start of the
//! input, and the write side uses a single designated default engine (there is
//! no magic to dispatch on when encrypting).
//!
//! The engines are deliberately independent implementations rather than one
//! parameterized code path: an old format's code should never change just
//! because a new format was added.

use crate::error::{ErrorCategory, ErrorKind, Result, SaltyboxError};
use crate::{secretcrypt_v1, varmor};
use zeroize::Zeroizing;

/// One saltybox on-disk format: an armor magic paired with the cryptography
/// that produces and consumes the armored payload.
///
/// The magic belongs to the engine rather than to a central table so an
/// engine can incorporate it into what it authenticates (a future format
/// feeds its magic to the AEAD as associated data).
///
/// The read side is split into [`unarmor`](Self::unarmor) and
/// [`decrypt`](Self::decrypt) instead of a single call so callers can
/// attribute a failure to the armor layer vs. the cryptography — the CLI
/// reports those as distinct errors ("failed to unarmor" vs. "failed to
/// decrypt"), and collapsing the split would erase that diagnostic.
pub trait FormatEngine {
    /// The armor magic prefix identifying this format (e.g. `"saltybox1:"`).
    fn magic(&self) -> &'static str;

    /// Encrypt plaintext into a complete armored string, magic included.
    fn encrypt(&self, passphrase: &[u8], plaintext: &[u8]) -> Result<String>;

    /// Decode the armored string into the binary payload for
    /// [`decrypt`](Self::decrypt).
    ///
    /// The input must carry this engine's magic; callers are expected to have
    /// selected the engine via [`engine_for`] first.
    fn unarmor(&self, armored: &str) -> Result<Vec<u8>>;

    /// Decrypt a binary payload produced by [`unarmor`](Self::unarmor).
    ///
    /// There is no way to tell programmatically whether a failure is due to a
    /// bad passphrase or corrupted input; engines report both as
    /// authentication failures.
    fn decrypt(&self, passphrase: &[u8], payload: &[u8]) -> Result<Zeroizing<Vec<u8>>>;
}

/// The saltybox1 format: scrypt key derivation with XSalsa20-Poly1305,
/// armored per [`varmor`]. Delegates to the frozen v1 modules; this type adds
/// no logic of its own.
struct V1Engine;

impl FormatEngine for V1Engine {
    fn magic(&self) -> &'static str {
        varmor::V1_MAGIC
    }

    fn encrypt(&self, passphrase: &[u8], plaintext: &[u8]) -> Result<String> {
        let ciphertext = secretcrypt_v1::encrypt(passphrase, plaintext)?;
        Ok(varmor::wrap(&ciphertext))
    }

    fn unarmor(&self, armored: &str) -> Result<Vec<u8>> {
        varmor::unwrap(armored)
    }

    fn decrypt(&self, passphrase: &[u8], payload: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
        secretcrypt_v1::decrypt(passphrase, payload)
    }
}

/// Every supported engine, in the order the read side tries their magics.
const ENGINES: &[&dyn FormatEngine] = &[&V1Engine];

/// The engine used for all newly written files.
///
/// The write side has no input magic to dispatch on, so this selection is the
/// single point that decides what format saltybox produces. Decryption
/// support is intentionally broader: every engine in [`ENGINES`] stays
/// readable forever regardless of what this returns.
pub fn default_write_engine() -> &'static dyn FormatEngine {
    &V1Engine
}

/// Select the engine for an armored input by its magic.
///
/// Inputs matching no supported magic are diagnosed per scenario, mirroring
/// the taxonomy [`varmor::unwrap`] established (and using its exact message
/// strings, so dispatching here instead of in varmor is not a user-visible
/// change): a proper prefix of a supported magic is likely truncation, a
/// `saltybox` prefix that matches no supported version is from a future
/// saltybox, and anything else is not saltybox data at all.
pub fn engine_for(armored: &str) -> Result<&'static dyn FormatEngine> {
    for engine in ENGINES {
        if armored.starts_with(engine.magic()) {
            return Ok(*engine);
        }
    }

    if ENGINES
        .iter()
        .any(|engine| engine.magic().starts_with(armored))
    {
        // A proper prefix of a supported magic (including empty input) is
        // exactly what truncation at an unlucky offset would produce.
        Err(SaltyboxError::with_kind(
            ErrorCategory::User,
            ErrorKind::ArmoringInvalid,
            "input is a prefix of the magic marker; likely truncated",
        ))
    } else if armored.starts_with(varmor::MAGIC_PREFIX) {
        Err(SaltyboxError::with_kind(
            ErrorCategory::User,
            ErrorKind::ArmoringFromFuture,
            "input claims to be saltybox, but not a version we support",
        ))
    } else {
        Err(SaltyboxError::with_kind(
            ErrorCategory::User,
            ErrorKind::ArmoringInvalid,
            "input unrecognized as saltybox data",
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_engine_for_selects_v1() {
        let armored = default_write_engine().encrypt(b"pw", b"payload").unwrap();
        let engine = engine_for(&armored).unwrap();
        assert_eq!(engine.magic(), "saltybox1:");
    }

    #[test]
    fn test_default_write_engine_writes_v1() {
        let armored = default_write_engine().encrypt(b"pw", b"payload").unwrap();
        assert!(armored.starts_with("saltybox1:"));
    }

    #[test]
    fn test_roundtrip_through_dispatch() {
        let plaintext = b"hello world";
        let armored = default_write_engine().encrypt(b"pw", plaintext).unwrap();

        let engine = engine_for(&armored).unwrap();
        let payload = engine.unarmor(&armored).unwrap();
        let decrypted = engine.decrypt(b"pw", &payload).unwrap();
        assert_eq!(plaintext, &decrypted[..]);
    }

    #[test]
    fn test_wrong_passphrase_is_authentication_failure() {
        let armored = default_write_engine()
            .encrypt(b"correct", b"secret")
            .unwrap();

        let engine = engine_for(&armored).unwrap();
        let payload = engine.unarmor(&armored).unwrap();
        let err = engine
            .decrypt(b"wrong", &payload)
            .expect_err("expected authentication failure");
        assert_eq!(err.kind, Some(ErrorKind::AuthenticationFailed));
    }

    // The taxonomy tests below assert exact message strings: they pin that
    // dispatch reproduces varmor's diagnostics byte for byte, which is what
    // makes routing the CLI through this module a zero-functional-change
    // refactor.

    #[test]
    fn test_prefix_of_magic_is_truncated() {
        for input in ["", "salt", "saltybox", "saltybox1"] {
            let Err(err) = engine_for(input) else {
                panic!("expected error for {input:?}")
            };
            assert_eq!(
                err.kind,
                Some(ErrorKind::ArmoringInvalid),
                "input: {input:?}"
            );
            assert_eq!(
                err.message(),
                "input is a prefix of the magic marker; likely truncated",
                "input: {input:?}"
            );
        }
    }

    #[test]
    fn test_unsupported_version_is_from_future() {
        for input in ["saltybox2", "saltybox999999:..."] {
            let Err(err) = engine_for(input) else {
                panic!("expected error for {input:?}")
            };
            assert_eq!(
                err.kind,
                Some(ErrorKind::ArmoringFromFuture),
                "input: {input:?}"
            );
            assert_eq!(
                err.message(),
                "input claims to be saltybox, but not a version we support",
                "input: {input:?}"
            );
        }
    }

    #[test]
    fn test_non_saltybox_input_is_unrecognized() {
        for input in ["abc", "saltz", "salty box", "something else entirely"] {
            let Err(err) = engine_for(input) else {
                panic!("expected error for {input:?}")
            };
            assert_eq!(
                err.kind,
                Some(ErrorKind::ArmoringInvalid),
                "input: {input:?}"
            );
            assert_eq!(
                err.message(),
                "input unrecognized as saltybox data",
                "input: {input:?}"
            );
        }
    }
}
