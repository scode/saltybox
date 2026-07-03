//! saltybox2 format engine: Argon2id key derivation + XChaCha20-Poly1305.
//!
//! The armored form is `saltybox2:` followed by base64url (no padding) of
//! this binary payload:
//!
//! - salt: 16 bytes, random per file
//! - m: u32 big-endian, Argon2id memory cost in KiB
//! - t: u32 big-endian, Argon2id time cost (passes)
//! - p: u32 big-endian, Argon2id parallelism (lanes)
//! - nonce: 24 bytes, random per file
//! - ciphertext plus 16-byte Poly1305 tag: everything to end of input
//!
//! There is no length field: the file is the container, so the sealed data
//! simply runs to the end of the payload.
//!
//! KDF parameters live in the header so every historical file stays
//! decryptable when the write defaults change; the caps enforced before key
//! derivation keep a hostile file from turning the KDF into a memory or CPU
//! bomb. The AEAD associated data covers the armor magic and the entire
//! header, so a successful decrypt proves the whole envelope — version
//! identifier included — was untampered. The Argon2 version (0x13) and the
//! 32-byte key length are fixed properties of the saltybox2 format, not
//! header fields.

use crate::error::{ErrorCategory, ErrorKind, Result, SaltyboxError};
use crate::format::FormatEngine;
use argon2::{Algorithm, Argon2, Params, Version};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use rand::TryRng;
use rand::rngs::SysRng;
use zeroize::Zeroizing;

/// Version 2 magic marker.
pub const V2_MAGIC: &str = "saltybox2:";

/// Length of salt in bytes.
const SALT_LEN: usize = 16;

/// Length of the three big-endian u32 Argon2 parameter fields.
const PARAMS_LEN: usize = 12;

/// Length of nonce in bytes.
const NONCE_LEN: usize = 24;

/// Length of the full header (salt + params + nonce) preceding the sealed data.
const HEADER_LEN: usize = SALT_LEN + PARAMS_LEN + NONCE_LEN;

/// Length of the Poly1305 authentication tag appended to the ciphertext.
const TAG_LEN: usize = 16;

/// Length of derived key in bytes.
const KEY_LEN: usize = 32;

/// Argon2id memory cost written to new files, in KiB (256 MiB).
pub const DEFAULT_M_COST_KIB: u32 = 262144;

/// Argon2id time cost (passes) written to new files.
pub const DEFAULT_T_COST: u32 = 3;

/// Argon2id parallelism (lanes) written to new files.
///
/// Kept at 1 deliberately: the argon2 crate computes lanes serially unless
/// its rayon-based `parallel` feature is enabled, so a higher value would
/// add memory-bandwidth work without any speedup.
pub const DEFAULT_P_COST: u32 = 1;

/// Maximum Argon2id memory cost accepted when decrypting, in KiB (4 GiB).
///
/// The caps below exist so a hostile file cannot make decryption allocate
/// absurd memory or burn unbounded CPU merely by claiming huge parameters.
/// They are far above the write defaults, leaving headroom for future
/// default bumps without a format change.
pub const MAX_M_COST_KIB: u32 = 4194304;

/// Maximum Argon2id time cost accepted when decrypting.
pub const MAX_T_COST: u32 = 64;

/// Maximum Argon2id parallelism accepted when decrypting.
pub const MAX_P_COST: u32 = 8;

/// The saltybox2 format engine.
///
/// Unlike v1 (where armor and cryptography live in separate modules), this
/// engine owns its armor handling: the magic participates in authentication
/// as part of the AEAD associated data, so armor and crypto cannot be
/// separated without losing that binding.
pub struct V2Engine;

impl FormatEngine for V2Engine {
    fn magic(&self) -> &'static str {
        V2_MAGIC
    }

    fn encrypt(&self, passphrase: &[u8], plaintext: &[u8]) -> Result<String> {
        encrypt(passphrase, plaintext)
    }

    fn unarmor(&self, armored: &str) -> Result<Vec<u8>> {
        let encoded = armored.strip_prefix(V2_MAGIC).ok_or_else(|| {
            // Dispatch selects engines by magic, so reaching this without the
            // magic present indicates a caller bug, not bad user input.
            SaltyboxError::with_kind(
                ErrorCategory::Internal,
                ErrorKind::ArmoringInvalid,
                "input does not start with the saltybox2 magic",
            )
        })?;
        URL_SAFE_NO_PAD.decode(encoded).map_err(|e| {
            SaltyboxError::with_kind_and_source(
                ErrorCategory::User,
                ErrorKind::ArmoringDecode,
                "base64 decoding failed",
                e,
            )
        })
    }

    fn decrypt(&self, passphrase: &[u8], payload: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
        decrypt(passphrase, payload)
    }
}

/// Validate Argon2 parameters against the format's caps and floors.
///
/// Runs BEFORE any key derivation: this is the barrier that keeps
/// attacker-chosen parameters from becoming a resource bomb, so no caller
/// may derive a key from unvalidated parameters. Out-of-range parameters are
/// a format error, deliberately distinct from authentication failure.
fn validate_params(m_cost_kib: u32, t_cost: u32, p_cost: u32) -> Result<()> {
    if p_cost == 0 {
        return Err(SaltyboxError::with_kind(
            ErrorCategory::User,
            ErrorKind::BinaryFormat,
            "Argon2 parallelism must be at least 1",
        ));
    }
    if p_cost > MAX_P_COST {
        return Err(SaltyboxError::with_kind(
            ErrorCategory::User,
            ErrorKind::BinaryFormat,
            format!("Argon2 parallelism {p_cost} exceeds the supported maximum of {MAX_P_COST}"),
        ));
    }
    if t_cost == 0 {
        return Err(SaltyboxError::with_kind(
            ErrorCategory::User,
            ErrorKind::BinaryFormat,
            "Argon2 time cost must be at least 1",
        ));
    }
    if t_cost > MAX_T_COST {
        return Err(SaltyboxError::with_kind(
            ErrorCategory::User,
            ErrorKind::BinaryFormat,
            format!("Argon2 time cost {t_cost} exceeds the supported maximum of {MAX_T_COST}"),
        ));
    }
    if m_cost_kib > MAX_M_COST_KIB {
        return Err(SaltyboxError::with_kind(
            ErrorCategory::User,
            ErrorKind::BinaryFormat,
            format!(
                "Argon2 memory cost {m_cost_kib} KiB exceeds the supported maximum of {MAX_M_COST_KIB} KiB"
            ),
        ));
    }
    if m_cost_kib < 8 * p_cost {
        return Err(SaltyboxError::with_kind(
            ErrorCategory::User,
            ErrorKind::BinaryFormat,
            format!(
                "Argon2 memory cost {m_cost_kib} KiB is below the Argon2 minimum of {} KiB (8 KiB per lane)",
                8 * p_cost
            ),
        ));
    }
    Ok(())
}

/// Derive a 32-byte key with Argon2id v0x13.
///
/// Callers must have run [`validate_params`] first; this function trusts its
/// inputs and will happily allocate whatever memory the parameters demand.
fn derive_key(
    passphrase: &[u8],
    salt: &[u8; SALT_LEN],
    m_cost_kib: u32,
    t_cost: u32,
    p_cost: u32,
) -> Result<Zeroizing<[u8; KEY_LEN]>> {
    let params = Params::new(m_cost_kib, t_cost, p_cost, Some(KEY_LEN)).map_err(|e| {
        SaltyboxError::with_kind_and_source(
            ErrorCategory::Internal,
            ErrorKind::Argon2Failure,
            "failed to create Argon2 params",
            e,
        )
    })?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

    // Zeroization scope: the argon2 crate's `zeroize` feature (enabled in
    // Cargo.toml) wipes the key-equivalent intermediates inside the KDF —
    // the passphrase-derived initial hash H0 and the final block hash that
    // is the direct preimage of the key. The multi-hundred-MiB work buffer
    // itself is freed unwiped by this convenience path. Wiping it would
    // require self-managed memory via hash_password_into_with_memory, which
    // was tried and rejected: buffer setup/teardown compiled in this crate
    // runs at dev opt-level and added ~10s per operation to debug/test
    // builds. The residual exposure (work buffer contents in freed memory)
    // matches what v1's scrypt path has always had.
    let mut key = Zeroizing::new([0u8; KEY_LEN]);
    argon2
        .hash_password_into(passphrase, salt, &mut *key)
        .map_err(|e| {
            SaltyboxError::with_kind_and_source(
                ErrorCategory::Internal,
                ErrorKind::Argon2Failure,
                "Argon2 key derivation failed",
                e,
            )
        })?;

    Ok(key)
}

/// The AEAD associated data: armor magic followed by the full header.
///
/// Binding the magic means a valid saltybox2 file cannot be reinterpreted
/// under some other version's magic, and binding the header means salt,
/// parameters, and nonce are all tamper-evident on successful decrypt.
fn associated_data(header: &[u8]) -> Vec<u8> {
    [V2_MAGIC.as_bytes(), header].concat()
}

/// Generate a random byte array and normalize RNG failures into SaltyboxError.
fn fill_random_bytes<const N: usize>(error_msg: &'static str) -> Result<[u8; N]> {
    let mut bytes = [0u8; N];
    SysRng.try_fill_bytes(&mut bytes).map_err(|e| {
        SaltyboxError::with_kind_and_source(ErrorCategory::Internal, ErrorKind::Io, error_msg, e)
    })?;
    Ok(bytes)
}

/// Encrypt plaintext with a passphrase using random salt and nonce and the
/// default KDF parameters, returning the complete armored string.
pub fn encrypt(passphrase: &[u8], plaintext: &[u8]) -> Result<String> {
    let salt = fill_random_bytes::<SALT_LEN>("failed to generate random salt")?;
    let nonce = fill_random_bytes::<NONCE_LEN>("failed to generate random nonce")?;

    encrypt_deterministic(
        passphrase,
        plaintext,
        &salt,
        &nonce,
        DEFAULT_M_COST_KIB,
        DEFAULT_T_COST,
        DEFAULT_P_COST,
    )
}

/// Encrypt with caller-provided salt, nonce, and KDF parameters.
///
/// This exists so tests and golden vectors can produce deterministic output.
/// NEVER call it directly in production code — always use [`encrypt`], which
/// generates a fresh random salt and nonce (nonce reuse under the same key
/// destroys XChaCha20-Poly1305's confidentiality and authenticity).
pub fn encrypt_deterministic(
    passphrase: &[u8],
    plaintext: &[u8],
    salt: &[u8; SALT_LEN],
    nonce: &[u8; NONCE_LEN],
    m_cost_kib: u32,
    t_cost: u32,
    p_cost: u32,
) -> Result<String> {
    validate_params(m_cost_kib, t_cost, p_cost)?;
    let key = derive_key(passphrase, salt, m_cost_kib, t_cost, p_cost)?;

    let mut header = Vec::with_capacity(HEADER_LEN);
    header.extend_from_slice(salt);
    header.extend_from_slice(&m_cost_kib.to_be_bytes());
    header.extend_from_slice(&t_cost.to_be_bytes());
    header.extend_from_slice(&p_cost.to_be_bytes());
    header.extend_from_slice(nonce);

    let aad = associated_data(&header);
    let cipher = XChaCha20Poly1305::new((&*key).into());
    let ciphertext = cipher
        .encrypt(
            &XNonce::from(*nonce),
            Payload {
                msg: plaintext,
                aad: &aad,
            },
        )
        .map_err(|e| {
            SaltyboxError::with_kind(
                ErrorCategory::Internal,
                ErrorKind::AeadFailure,
                format!("encryption failed: {e}"),
            )
        })?;

    let mut payload = header;
    payload.extend_from_slice(&ciphertext);
    Ok(format!("{}{}", V2_MAGIC, URL_SAFE_NO_PAD.encode(payload)))
}

/// Decrypt a binary saltybox2 payload (the unarmored bytes after the magic).
///
/// Parameter validation runs before key derivation — see [`validate_params`]
/// for why that ordering is load-bearing. The plaintext is returned in a
/// `Zeroizing` buffer so it is wiped from memory on drop, matching the
/// treatment of the passphrase and derived key.
pub fn decrypt(passphrase: &[u8], payload: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    if payload.len() < SALT_LEN {
        return Err(SaltyboxError::with_kind(
            ErrorCategory::User,
            ErrorKind::TruncatedInput,
            "input likely truncated while reading salt",
        ));
    }
    if payload.len() < SALT_LEN + PARAMS_LEN {
        return Err(SaltyboxError::with_kind(
            ErrorCategory::User,
            ErrorKind::TruncatedInput,
            "input likely truncated while reading Argon2 parameters",
        ));
    }
    if payload.len() < HEADER_LEN {
        return Err(SaltyboxError::with_kind(
            ErrorCategory::User,
            ErrorKind::TruncatedInput,
            "input likely truncated while reading nonce",
        ));
    }

    let header = &payload[..HEADER_LEN];
    let salt: [u8; SALT_LEN] = header[..SALT_LEN]
        .try_into()
        .expect("bounds check above guarantees a full salt field");
    let m_cost_kib = u32::from_be_bytes(
        header[SALT_LEN..SALT_LEN + 4]
            .try_into()
            .expect("header length guarantees a full m field"),
    );
    let t_cost = u32::from_be_bytes(
        header[SALT_LEN + 4..SALT_LEN + 8]
            .try_into()
            .expect("header length guarantees a full t field"),
    );
    let p_cost = u32::from_be_bytes(
        header[SALT_LEN + 8..SALT_LEN + 12]
            .try_into()
            .expect("header length guarantees a full p field"),
    );
    let nonce: [u8; NONCE_LEN] = header[SALT_LEN + PARAMS_LEN..]
        .try_into()
        .expect("header length guarantees a full nonce field");

    let sealed = &payload[HEADER_LEN..];
    if sealed.len() < TAG_LEN {
        return Err(SaltyboxError::with_kind(
            ErrorCategory::User,
            ErrorKind::TruncatedInput,
            "input likely truncated while reading sealed data (shorter than the authentication tag)",
        ));
    }

    validate_params(m_cost_kib, t_cost, p_cost)?;
    let key = derive_key(passphrase, &salt, m_cost_kib, t_cost, p_cost)?;

    let aad = associated_data(header);
    let cipher = XChaCha20Poly1305::new((&*key).into());
    let plaintext = cipher
        .decrypt(
            &XNonce::from(nonce),
            Payload {
                msg: sealed,
                aad: &aad,
            },
        )
        .map_err(|_| {
            SaltyboxError::with_kind(
                ErrorCategory::User,
                ErrorKind::AuthenticationFailed,
                "corrupt input, tampered-with data, or bad passphrase",
            )
        })?;

    Ok(Zeroizing::new(plaintext))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Small-but-valid parameters so the suite stays fast; the write
    /// defaults are exercised once in `test_default_params_roundtrip`.
    const TEST_M: u32 = 8192;
    const TEST_T: u32 = 3;
    const TEST_P: u32 = 1;

    const TEST_SALT: [u8; SALT_LEN] = [0x42; SALT_LEN];
    const TEST_NONCE: [u8; NONCE_LEN] = [0x24; NONCE_LEN];

    /// Offsets of the parameter fields within the binary payload.
    const M_OFFSET: usize = SALT_LEN;
    const T_OFFSET: usize = SALT_LEN + 4;
    const P_OFFSET: usize = SALT_LEN + 8;

    fn small_payload(passphrase: &[u8], plaintext: &[u8]) -> Vec<u8> {
        let armored = encrypt_deterministic(
            passphrase,
            plaintext,
            &TEST_SALT,
            &TEST_NONCE,
            TEST_M,
            TEST_T,
            TEST_P,
        )
        .unwrap();
        V2Engine.unarmor(&armored).unwrap()
    }

    /// Build a payload with arbitrary header parameters and dummy sealed
    /// data. Only useful for exercising validation that fires before any
    /// authentication happens.
    fn crafted_payload(m_cost_kib: u32, t_cost: u32, p_cost: u32) -> Vec<u8> {
        let mut payload = Vec::new();
        payload.extend_from_slice(&TEST_SALT);
        payload.extend_from_slice(&m_cost_kib.to_be_bytes());
        payload.extend_from_slice(&t_cost.to_be_bytes());
        payload.extend_from_slice(&p_cost.to_be_bytes());
        payload.extend_from_slice(&TEST_NONCE);
        payload.extend_from_slice(&[0u8; TAG_LEN]);
        payload
    }

    #[test]
    fn test_roundtrip() {
        for plaintext in [
            &b""[..],
            b"hello",
            &[0u8; 100],
            &(0..=255u8).collect::<Vec<_>>(),
        ] {
            let payload = small_payload(b"pw", plaintext);
            let decrypted = decrypt(b"pw", &payload).unwrap();
            assert_eq!(plaintext, &decrypted[..]);
        }
    }

    #[test]
    fn test_engine_roundtrip_through_armor() {
        let armored = V2Engine.encrypt(b"pw", b"engine roundtrip").unwrap();
        assert!(armored.starts_with("saltybox2:"));

        let payload = V2Engine.unarmor(&armored).unwrap();
        let decrypted = V2Engine.decrypt(b"pw", &payload).unwrap();
        assert_eq!(b"engine roundtrip", &decrypted[..]);
    }

    /// One test at the real write defaults (256 MiB) so a broken default
    /// configuration cannot hide behind the small test parameters.
    #[test]
    fn test_default_params_roundtrip() {
        let armored = encrypt(b"pw", b"default params").unwrap();
        let payload = V2Engine.unarmor(&armored).unwrap();
        assert_eq!(
            u32::from_be_bytes(payload[M_OFFSET..M_OFFSET + 4].try_into().unwrap()),
            DEFAULT_M_COST_KIB
        );
        assert_eq!(
            u32::from_be_bytes(payload[T_OFFSET..T_OFFSET + 4].try_into().unwrap()),
            DEFAULT_T_COST
        );
        assert_eq!(
            u32::from_be_bytes(payload[P_OFFSET..P_OFFSET + 4].try_into().unwrap()),
            DEFAULT_P_COST
        );
        let decrypted = decrypt(b"pw", &payload).unwrap();
        assert_eq!(b"default params", &decrypted[..]);
    }

    #[test]
    fn test_random_encryption_uses_fresh_salt_and_nonce() {
        let first = V2Engine.unarmor(&encrypt(b"pw", b"same").unwrap()).unwrap();
        let second = V2Engine.unarmor(&encrypt(b"pw", b"same").unwrap()).unwrap();

        assert_ne!(first[..SALT_LEN], second[..SALT_LEN]);
        assert_ne!(
            first[SALT_LEN + PARAMS_LEN..HEADER_LEN],
            second[SALT_LEN + PARAMS_LEN..HEADER_LEN]
        );
    }

    #[test]
    fn test_wrong_passphrase() {
        let payload = small_payload(b"correct", b"secret");
        let err = decrypt(b"wrong", &payload).expect_err("expected authentication failure");
        assert_eq!(err.kind, Some(ErrorKind::AuthenticationFailed));
    }

    #[test]
    fn test_tampered_ciphertext() {
        // First sealed byte is ciphertext proper; the last byte is inside the
        // Poly1305 tag. Both corruptions must fail authentication.
        for offset_from in ["start", "end"] {
            let mut payload = small_payload(b"pw", b"secret");
            match offset_from {
                "start" => payload[HEADER_LEN] ^= 0x01,
                _ => *payload.last_mut().unwrap() ^= 0x01,
            }
            let err = decrypt(b"pw", &payload).expect_err("expected authentication failure");
            assert_eq!(
                err.kind,
                Some(ErrorKind::AuthenticationFailed),
                "tampered at sealed data {offset_from}"
            );
        }
    }

    /// Header flips that keep parameters in range must fail authentication:
    /// salt and nonce feed the KDF/AEAD directly, and the in-range parameter
    /// change is caught by the AAD binding (the KDF also changes, but either
    /// way decryption must not succeed).
    #[test]
    fn test_tampered_header_in_range_is_authentication_failure() {
        // (offset, new_value): salt byte, nonce byte, t low byte 3 -> 2 (in range).
        let cases = [
            (0usize, None),
            (SALT_LEN + PARAMS_LEN, None),
            (T_OFFSET + 3, Some(2u8)),
        ];
        for (offset, replacement) in cases {
            let mut payload = small_payload(b"pw", b"secret");
            match replacement {
                Some(value) => payload[offset] = value,
                None => payload[offset] ^= 0x01,
            }
            let err = decrypt(b"pw", &payload)
                .expect_err(&format!("expected auth failure for offset {offset}"));
            assert_eq!(
                err.kind,
                Some(ErrorKind::AuthenticationFailed),
                "offset: {offset}"
            );
        }
    }

    /// Header flips that push a parameter out of range must fail parameter
    /// validation (a format error), before any key derivation runs.
    #[test]
    fn test_tampered_header_out_of_range_is_format_error() {
        // Flipping the top byte of m (8192 -> 16785408 KiB) exceeds the cap.
        let mut payload = small_payload(b"pw", b"secret");
        payload[M_OFFSET] = 0x01;
        let err = decrypt(b"pw", &payload).expect_err("expected format error for huge m");
        assert_eq!(err.kind, Some(ErrorKind::BinaryFormat));

        // Zeroing p violates the p >= 1 floor.
        let mut payload = small_payload(b"pw", b"secret");
        payload[P_OFFSET + 3] = 0;
        let err = decrypt(b"pw", &payload).expect_err("expected format error for p = 0");
        assert_eq!(err.kind, Some(ErrorKind::BinaryFormat));
    }

    #[test]
    fn test_truncation_at_every_field_boundary() {
        let payload = small_payload(b"pw", b"secret");
        let cases = [
            (0, "input likely truncated while reading salt"),
            (SALT_LEN - 1, "input likely truncated while reading salt"),
            (
                SALT_LEN,
                "input likely truncated while reading Argon2 parameters",
            ),
            (
                SALT_LEN + PARAMS_LEN - 1,
                "input likely truncated while reading Argon2 parameters",
            ),
            (
                SALT_LEN + PARAMS_LEN,
                "input likely truncated while reading nonce",
            ),
            (HEADER_LEN - 1, "input likely truncated while reading nonce"),
            (
                HEADER_LEN,
                "input likely truncated while reading sealed data (shorter than the authentication tag)",
            ),
            (
                HEADER_LEN + TAG_LEN - 1,
                "input likely truncated while reading sealed data (shorter than the authentication tag)",
            ),
        ];
        for (len, expected_msg) in cases {
            let err = decrypt(b"pw", &payload[..len])
                .expect_err(&format!("expected truncation error at length {len}"));
            assert_eq!(err.kind, Some(ErrorKind::TruncatedInput), "length: {len}");
            assert_eq!(err.message(), expected_msg, "length: {len}");
        }
    }

    /// Truncating into the sealed data (but past the tag length) leaves a
    /// structurally valid payload whose authentication must fail.
    #[test]
    fn test_truncated_sealed_data_is_authentication_failure() {
        let payload = small_payload(b"pw", b"longer secret so truncation leaves the tag length");
        let err = decrypt(b"pw", &payload[..payload.len() - 1])
            .expect_err("expected authentication failure");
        assert_eq!(err.kind, Some(ErrorKind::AuthenticationFailed));
    }

    /// Every cap and floor rejects via crafted headers, without running the
    /// KDF. Acceptance at the caps is deliberately NOT tested: proving
    /// m = 4 GiB is accepted would require actually allocating 4 GiB.
    #[test]
    fn test_parameter_caps_and_floors_reject() {
        // Expected messages are asserted exactly so each case pins its own
        // validation branch: a mis-wired comparison could otherwise return
        // the right kind from the wrong check.
        let cases = [
            (
                MAX_M_COST_KIB + 1,
                TEST_T,
                TEST_P,
                "Argon2 memory cost 4194305 KiB exceeds the supported maximum of 4194304 KiB",
            ),
            (
                TEST_M,
                MAX_T_COST + 1,
                TEST_P,
                "Argon2 time cost 65 exceeds the supported maximum of 64",
            ),
            (
                TEST_M,
                TEST_T,
                MAX_P_COST + 1,
                "Argon2 parallelism 9 exceeds the supported maximum of 8",
            ),
            (TEST_M, 0, TEST_P, "Argon2 time cost must be at least 1"),
            (TEST_M, TEST_T, 0, "Argon2 parallelism must be at least 1"),
            (
                15,
                TEST_T,
                2,
                "Argon2 memory cost 15 KiB is below the Argon2 minimum of 16 KiB (8 KiB per lane)",
            ),
        ];
        for (m, t, p, expected_msg) in cases {
            let err = decrypt(b"pw", &crafted_payload(m, t, p))
                .expect_err(&format!("expected format error: {expected_msg}"));
            assert_eq!(err.kind, Some(ErrorKind::BinaryFormat), "{expected_msg}");
            assert_eq!(err.message(), expected_msg);
        }
    }

    #[test]
    fn test_encrypt_rejects_invalid_params() {
        let err = encrypt_deterministic(
            b"pw",
            b"data",
            &TEST_SALT,
            &TEST_NONCE,
            MAX_M_COST_KIB + 1,
            TEST_T,
            TEST_P,
        )
        .expect_err("expected format error on encrypt");
        assert_eq!(err.kind, Some(ErrorKind::BinaryFormat));
    }

    #[test]
    fn test_unarmor_rejects_bad_base64() {
        let err = V2Engine
            .unarmor("saltybox2:bad$$")
            .expect_err("expected base64 decode failure");
        assert_eq!(err.kind, Some(ErrorKind::ArmoringDecode));
    }

    #[test]
    fn test_deterministic_encryption() {
        let make = || {
            encrypt_deterministic(
                b"pw",
                b"stable output",
                &TEST_SALT,
                &TEST_NONCE,
                TEST_M,
                TEST_T,
                TEST_P,
            )
            .unwrap()
        };
        assert_eq!(make(), make());
    }
}
