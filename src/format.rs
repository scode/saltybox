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
use crate::format_v2::V2Engine;
use crate::{secretcrypt_v1, varmor};
use zeroize::Zeroizing;

/// One saltybox on-disk format: an armor magic paired with the cryptography
/// that produces and consumes the armored payload.
///
/// Each engine carries its own magic, rather than a central table mapping
/// magic strings to engines. The reason: the magic is part of the on-disk
/// format itself, not just routing metadata. A format may want tampering
/// with the version marker to be detectable, which it achieves by mixing
/// the magic into the data its cipher authenticates alongside the
/// ciphertext (the AEAD's "associated data") — something an engine can
/// only do if the magic is its own to know about.
///
/// Why version-marker tampering matters: imagine a future format version
/// that is byte-for-byte identical to an existing one except the plaintext
/// is compressed before encryption. Relabel such a file with the other
/// version's magic, and — if the magic is unauthenticated — everything the
/// cipher checks is unchanged: the tag verifies, decryption "succeeds", and
/// the user is handed compressed bytes as their document. With the magic
/// authenticated, any relabeling fails the tag check instead. Versions
/// that differ in cipher or layout make relabeling fail by accident;
/// authenticating the magic makes it fail by design.
///
/// The read side is split into [`unarmor`](Self::unarmor) and
/// [`decrypt`](Self::decrypt) instead of a single call so callers can
/// attribute a failure to the armor layer vs. the cryptography — the CLI
/// reports those as distinct errors ("failed to unarmor" vs. "failed to
/// decrypt").
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
    /// Tampering within the authenticated ciphertext is indistinguishable
    /// from a bad passphrase, so both surface as authentication failures.
    /// Structurally malformed payloads (truncated fields, bad lengths,
    /// trailing data) may get more specific diagnostics instead.
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
///
/// Engines are never removed: every format ever written stays decryptable.
const ENGINES: &[&dyn FormatEngine] = &[&V1Engine, &V2Engine];

/// The engine used for all newly written files.
///
/// The write side has no input magic to dispatch on, so this selection is the
/// single point that decides what format saltybox produces. Decryption
/// support is intentionally broader: every engine in `ENGINES` stays
/// readable forever regardless of what this returns.
pub fn default_write_engine() -> &'static dyn FormatEngine {
    &V1Engine
}

/// Select the engine for an armored input and decode its payload in one step.
///
/// The read side always needs [`engine_for`] and
/// [`unarmor`](FormatEngine::unarmor) together; bundling them keeps call
/// sites from duplicating the pairing. Both halves report failures the CLI
/// frames identically (armor-layer errors), so combining them loses no
/// diagnostic precision.
pub fn decode(armored: &str) -> Result<(&'static dyn FormatEngine, Vec<u8>)> {
    let engine = engine_for(armored)?;
    let payload = engine.unarmor(armored)?;
    Ok((engine, payload))
}

/// Select the engine for an armored input by its magic.
///
/// Inputs matching no supported magic are diagnosed per scenario: a proper
/// prefix of any supported magic reads as likely truncation, a `saltybox`
/// prefix that matches no supported version as coming from a future
/// saltybox, and anything else as not saltybox data at all.
///
/// The CLI's diagnostics for unrecognized input come from here: raw input
/// is classified before any engine sees it, relative to the full set of
/// supported versions — bare "saltybox2" reads as likely truncation, for
/// example, since it is a proper prefix of a supported magic.
/// [`varmor::unwrap`] carries equivalent v1-only branches with identical
/// message strings for its direct callers; the duplication is deliberate,
/// keeping varmor self-contained.
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

    /// Engine selection by magic, and behavior that flows through the
    /// selected engine.
    mod dispatch {
        use super::*;

        #[test]
        fn engine_for_selects_v1() {
            let armored = default_write_engine().encrypt(b"pw", b"payload").unwrap();
            let engine = engine_for(&armored).unwrap();
            assert_eq!(engine.magic(), "saltybox1:");
        }

        #[test]
        fn default_write_engine_writes_v1() {
            let armored = default_write_engine().encrypt(b"pw", b"payload").unwrap();
            assert!(armored.starts_with("saltybox1:"));
        }

        #[test]
        fn engine_for_selects_v2() {
            let armored = V2Engine.encrypt(b"pw", b"payload").unwrap();
            let engine = engine_for(&armored).unwrap();
            assert_eq!(engine.magic(), "saltybox2:");
        }

        #[test]
        fn roundtrip_through_dispatch() {
            let plaintext = b"hello world";
            let armored = default_write_engine().encrypt(b"pw", plaintext).unwrap();

            let (engine, payload) = decode(&armored).unwrap();
            let decrypted = engine.decrypt(b"pw", &payload).unwrap();
            assert_eq!(plaintext, &decrypted[..]);
        }

        #[test]
        fn v2_roundtrip_through_dispatch() {
            let plaintext = b"v2 dispatch roundtrip";
            let armored = V2Engine.encrypt(b"pw", plaintext).unwrap();

            let (engine, payload) = decode(&armored).unwrap();
            let decrypted = engine.decrypt(b"pw", &payload).unwrap();
            assert_eq!(plaintext, &decrypted[..]);
        }

        #[test]
        fn magic_with_malformed_body_dispatches_to_engine() {
            // Dispatch selects on the magic prefix alone: a valid magic with a
            // malformed body still selects that engine, whose unarmor then
            // reports the decode error.
            let input = "saltybox1:bad$$";
            let engine = engine_for(input).unwrap();
            assert_eq!(engine.magic(), "saltybox1:");

            let err = engine
                .unarmor(input)
                .expect_err("expected base64 decode failure");
            assert_eq!(err.kind, Some(ErrorKind::ArmoringDecode));
        }

        #[test]
        fn unarmor_rejects_non_canonical_base64() {
            // SPEC.md requires canonical armor: padding characters ("AA==") and
            // non-zero trailing bits ("AB") must be rejected. This currently
            // holds via the base64 crate's URL_SAFE_NO_PAD defaults; pinning it
            // here keeps a dependency upgrade from silently loosening the format.
            for input in [
                "saltybox1:AA==",
                "saltybox2:AA==:end",
                "saltybox1:AB",
                "saltybox2:AB:end",
            ] {
                let engine = engine_for(input).unwrap();
                let err = engine
                    .unarmor(input)
                    .expect_err(&format!("expected canonicality rejection for {input:?}"));
                assert_eq!(
                    err.kind,
                    Some(ErrorKind::ArmoringDecode),
                    "input: {input:?}"
                );
            }
        }

        #[test]
        fn wrong_passphrase_is_authentication_failure() {
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
    }

    /// The tests below assert exact message strings: the diagnostics for
    /// unrecognized input are user-visible CLI behavior, so a wording change
    /// is a behavior change and must show up in a test diff.
    mod diagnostics {
        use super::*;

        #[test]
        fn prefix_of_magic_is_truncated() {
            // Bare "saltybox2" is a proper prefix of the saltybox2 magic, so it
            // reads as likely truncation rather than as an unsupported version.
            for input in ["", "salt", "saltybox", "saltybox1", "saltybox2"] {
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
        fn unsupported_version_is_from_future() {
            for input in ["saltybox3", "saltybox3:...", "saltybox999999:..."] {
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
        fn non_saltybox_input_is_unrecognized() {
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
}
