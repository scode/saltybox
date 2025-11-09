//! Golden test vector validation

use anyhow::Result;
use base64::{Engine, engine::general_purpose::STANDARD as BASE64_STANDARD};
use serde::Deserialize;

#[derive(Debug, Deserialize)]
struct GoldenVector {
    plaintext: String,
    ciphertext: String,
    passphrase: String,
    nonce: String,
    salt: String,
    comment: String,
}

fn load_golden_vectors() -> Result<Vec<GoldenVector>> {
    let json_data = include_str!("../testdata/golden-vectors.json");
    let vectors: Vec<GoldenVector> = serde_json::from_str(json_data)?;
    Ok(vectors)
}

/// Run golden vector tests on specified indices
///
/// If `indices` is None, tests all vectors. Otherwise tests only
/// the specified indices.
fn run_golden_vector_tests(indices: Option<&[usize]>) {
    let vectors = load_golden_vectors().expect("failed to load golden vectors");

    // Validate indices are within bounds
    if let Some(idx) = indices {
        for &i in idx {
            assert!(
                i < vectors.len(),
                "Index {} is out of bounds (only {} vectors available)",
                i,
                vectors.len()
            );
        }
    }

    let (test_description, iter): (String, Box<dyn Iterator<Item = (usize, &GoldenVector)>>) =
        match indices {
            Some(idx) => (
                format!("Testing {} selected golden vectors", idx.len()),
                Box::new(idx.iter().map(|&i| (i, &vectors[i]))),
            ),
            None => (
                format!("Testing {} golden vectors", vectors.len()),
                Box::new(vectors.iter().enumerate()),
            ),
        };

    println!("{}", test_description);

    let mut passed = 0;
    let mut failed = 0;

    for (i, vector) in iter {
        let expected_plaintext = BASE64_STANDARD
            .decode(&vector.plaintext)
            .expect("failed to decode plaintext");
        let passphrase = BASE64_STANDARD
            .decode(&vector.passphrase)
            .expect("failed to decode passphrase");
        let salt = BASE64_STANDARD
            .decode(&vector.salt)
            .expect("failed to decode salt");
        let nonce = BASE64_STANDARD
            .decode(&vector.nonce)
            .expect("failed to decode nonce");

        if salt.len() != 8 {
            eprintln!(
                "Vector {}: FAILED - salt must be 8 bytes, got {}",
                i,
                salt.len()
            );
            eprintln!("  Comment: {}", vector.comment);
            failed += 1;
            continue;
        }
        if nonce.len() != 24 {
            eprintln!(
                "Vector {}: FAILED - nonce must be 24 bytes, got {}",
                i,
                nonce.len()
            );
            eprintln!("  Comment: {}", vector.comment);
            failed += 1;
            continue;
        }

        // Test deterministic encryption produces exact ciphertext
        let encrypted = match saltybox::secretcrypt::encrypt_deterministic(
            &passphrase,
            &expected_plaintext,
            &salt.try_into().unwrap(),
            &nonce.try_into().unwrap(),
        ) {
            Ok(data) => data,
            Err(e) => {
                eprintln!("Vector {}: FAILED to encrypt - {}", i, e);
                eprintln!("  Comment: {}", vector.comment);
                failed += 1;
                continue;
            }
        };

        let wrapped = saltybox::varmor::wrap(&encrypted);

        if wrapped != vector.ciphertext {
            eprintln!("Vector {}: FAILED - ciphertext mismatch", i);
            eprintln!("  Comment: {}", vector.comment);
            eprintln!("  Expected: {}", vector.ciphertext);
            eprintln!("  Actual:   {}", wrapped);
            failed += 1;
            continue;
        }

        // Also test decryption works (round-trip validation)
        let unwrapped = match saltybox::varmor::unwrap(&vector.ciphertext) {
            Ok(data) => data,
            Err(e) => {
                eprintln!("Vector {}: FAILED to unwrap - {}", i, e);
                eprintln!("  Comment: {}", vector.comment);
                failed += 1;
                continue;
            }
        };

        let decrypted = match saltybox::secretcrypt::decrypt(&passphrase, &unwrapped) {
            Ok(data) => data,
            Err(e) => {
                eprintln!("Vector {}: FAILED to decrypt - {}", i, e);
                eprintln!("  Comment: {}", vector.comment);
                failed += 1;
                continue;
            }
        };

        if decrypted != expected_plaintext {
            eprintln!("Vector {}: FAILED - plaintext mismatch", i);
            eprintln!("  Comment: {}", vector.comment);
            eprintln!("  Expected length: {}", expected_plaintext.len());
            eprintln!("  Actual length: {}", decrypted.len());
            failed += 1;
            continue;
        }

        passed += 1;
    }

    let total = passed + failed;
    println!(
        "Results: {} passed, {} failed out of {} total",
        passed, failed, total
    );

    assert_eq!(failed, 0, "Some golden vectors failed validation");
    assert!(passed > 0, "No golden vectors were tested");
}

/// Test a small subset of diverse golden vectors for regular testing
/// (speed in debug mode makes these tests slow due to scrypt).
#[test]
fn test_golden_vectors_subset() {
    // Indices chosen to cover different types: empty plaintext, basic text, binary data
    let test_indices = [22, 24, 27];
    run_golden_vector_tests(Some(&test_indices));
}

/// Test all golden vectors (run with --ignored flag)
///
/// Run with: cargo test test_all_golden_vectors -- --ignored
#[test]
#[ignore]
fn test_all_golden_vectors() {
    run_golden_vector_tests(None);
}
