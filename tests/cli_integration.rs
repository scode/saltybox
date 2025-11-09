//! CLI integration tests
//!
//! Tests the command-line interface end-to-end.

use std::fs;
use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use tempfile::TempDir;

/// Get path to the saltybox binary
fn saltybox_bin() -> PathBuf {
    let mut path = std::env::current_exe().unwrap();
    path.pop(); // Remove test binary name
    path.pop(); // Remove deps/
    path.push("saltybox");
    path
}

/// Run saltybox with passphrase from stdin
fn run_saltybox_with_passphrase(
    args: &[&str],
    passphrase: &str,
) -> Result<std::process::Output, std::io::Error> {
    let mut child = Command::new(saltybox_bin())
        .arg("--passphrase-stdin")
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;

    {
        let stdin = child.stdin.as_mut().expect("failed to open stdin");
        // Ignore BrokenPipe errors - the command may exit before reading stdin
        // if it encounters an error (e.g., file not found)
        let _ = stdin.write_all(passphrase.as_bytes());
    }

    child.wait_with_output()
}

/// Get path to testdata directory
fn testdata_path(filename: &str) -> PathBuf {
    let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.push("testdata");
    path.push(filename);
    path
}

/// Decrypt known ciphertext.
#[test]
fn test_decrypt_known_ciphertext() {
    let temp_dir = TempDir::new().unwrap();
    let output = temp_dir.path().join("hello-decrypted.txt");

    let result = run_saltybox_with_passphrase(
        &[
            "decrypt",
            "-i",
            testdata_path("hello.txt.salty").to_str().unwrap(),
            "-o",
            output.to_str().unwrap(),
        ],
        "test",
    )
    .unwrap();

    assert!(
        result.status.success(),
        "decrypt failed: {}",
        String::from_utf8_lossy(&result.stderr)
    );

    let decrypted = fs::read_to_string(&output).unwrap();
    let expected = fs::read_to_string(testdata_path("hello.txt")).unwrap();
    assert_eq!(decrypted, expected);
}

#[test]
fn test_encrypt_decrypt_roundtrip() {
    let temp_dir = TempDir::new().unwrap();
    let plaintext_path = testdata_path("hello.txt");
    let encrypted_path = temp_dir.path().join("hello-encrypted.txt.salty");
    let decrypted_path = temp_dir.path().join("hello-decrypted.txt");

    let result = run_saltybox_with_passphrase(
        &[
            "encrypt",
            "-i",
            plaintext_path.to_str().unwrap(),
            "-o",
            encrypted_path.to_str().unwrap(),
        ],
        "test",
    )
    .unwrap();

    assert!(
        result.status.success(),
        "encrypt failed: {}",
        String::from_utf8_lossy(&result.stderr)
    );

    let result = run_saltybox_with_passphrase(
        &[
            "decrypt",
            "-i",
            encrypted_path.to_str().unwrap(),
            "-o",
            decrypted_path.to_str().unwrap(),
        ],
        "test",
    )
    .unwrap();

    assert!(
        result.status.success(),
        "decrypt failed: {}",
        String::from_utf8_lossy(&result.stderr)
    );

    let original = fs::read_to_string(&plaintext_path).unwrap();
    let decrypted = fs::read_to_string(&decrypted_path).unwrap();
    assert_eq!(original, decrypted);
}

#[test]
fn test_update_operation() {
    let temp_dir = TempDir::new().unwrap();
    let plaintext1 = temp_dir.path().join("plaintext1.txt");
    let plaintext2 = temp_dir.path().join("plaintext2.txt");
    let encrypted = temp_dir.path().join("encrypted.txt.salty");
    let decrypted = temp_dir.path().join("decrypted.txt");

    fs::write(&plaintext1, "Original content").unwrap();

    let result = run_saltybox_with_passphrase(
        &[
            "encrypt",
            "-i",
            plaintext1.to_str().unwrap(),
            "-o",
            encrypted.to_str().unwrap(),
        ],
        "test",
    )
    .unwrap();
    assert!(result.status.success());

    fs::write(&plaintext2, "Updated content").unwrap();

    let result = run_saltybox_with_passphrase(
        &[
            "update",
            "-i",
            plaintext2.to_str().unwrap(),
            "-o",
            encrypted.to_str().unwrap(),
        ],
        "test",
    )
    .unwrap();
    assert!(
        result.status.success(),
        "update failed: {}",
        String::from_utf8_lossy(&result.stderr)
    );

    let result = run_saltybox_with_passphrase(
        &[
            "decrypt",
            "-i",
            encrypted.to_str().unwrap(),
            "-o",
            decrypted.to_str().unwrap(),
        ],
        "test",
    )
    .unwrap();
    assert!(result.status.success());

    let decrypted_content = fs::read_to_string(&decrypted).unwrap();
    assert_eq!(decrypted_content, "Updated content");
}

#[test]
fn test_update_with_wrong_passphrase_fails() {
    let temp_dir = TempDir::new().unwrap();
    let plaintext1 = temp_dir.path().join("plaintext1.txt");
    let plaintext2 = temp_dir.path().join("plaintext2.txt");
    let encrypted = temp_dir.path().join("encrypted.txt.salty");

    fs::write(&plaintext1, "Original").unwrap();
    let result = run_saltybox_with_passphrase(
        &[
            "encrypt",
            "-i",
            plaintext1.to_str().unwrap(),
            "-o",
            encrypted.to_str().unwrap(),
        ],
        "correct_password",
    )
    .unwrap();
    assert!(result.status.success());

    fs::write(&plaintext2, "Updated").unwrap();
    let result = run_saltybox_with_passphrase(
        &[
            "update",
            "-i",
            plaintext2.to_str().unwrap(),
            "-o",
            encrypted.to_str().unwrap(),
        ],
        "wrong_password",
    )
    .unwrap();

    assert!(!result.status.success());
    let stderr = String::from_utf8_lossy(&result.stderr);
    assert!(
        stderr.contains("decrypt") || stderr.contains("passphrase"),
        "Expected error message about decryption/passphrase, got: {}",
        stderr
    );
}

#[test]
fn test_decrypt_nonexistent_file_fails() {
    let temp_dir = TempDir::new().unwrap();
    let nonexistent = temp_dir.path().join("nonexistent.salty");
    let output = temp_dir.path().join("output.txt");

    let result = run_saltybox_with_passphrase(
        &[
            "decrypt",
            "-i",
            nonexistent.to_str().unwrap(),
            "-o",
            output.to_str().unwrap(),
        ],
        "test",
    )
    .unwrap();

    assert!(!result.status.success());
    assert!(!output.exists());
}

#[test]
fn test_empty_file_roundtrip() {
    let temp_dir = TempDir::new().unwrap();
    let plaintext = temp_dir.path().join("empty.txt");
    let encrypted = temp_dir.path().join("empty.txt.salty");
    let decrypted = temp_dir.path().join("empty-decrypted.txt");

    fs::write(&plaintext, b"").unwrap();

    let result = run_saltybox_with_passphrase(
        &[
            "encrypt",
            "-i",
            plaintext.to_str().unwrap(),
            "-o",
            encrypted.to_str().unwrap(),
        ],
        "test",
    )
    .unwrap();
    assert!(result.status.success());

    let result = run_saltybox_with_passphrase(
        &[
            "decrypt",
            "-i",
            encrypted.to_str().unwrap(),
            "-o",
            decrypted.to_str().unwrap(),
        ],
        "test",
    )
    .unwrap();

    assert!(result.status.success());
    let content = fs::read(&decrypted).unwrap();
    assert_eq!(content, b"");
}

#[test]
fn test_large_file_roundtrip() {
    let temp_dir = TempDir::new().unwrap();
    let plaintext = temp_dir.path().join("large.txt");
    let encrypted = temp_dir.path().join("large.txt.salty");
    let decrypted = temp_dir.path().join("large-decrypted.txt");

    let large_content = vec![0x42u8; 1024 * 1024];
    fs::write(&plaintext, &large_content).unwrap();

    let result = run_saltybox_with_passphrase(
        &[
            "encrypt",
            "-i",
            plaintext.to_str().unwrap(),
            "-o",
            encrypted.to_str().unwrap(),
        ],
        "test",
    )
    .unwrap();
    assert!(result.status.success());

    let result = run_saltybox_with_passphrase(
        &[
            "decrypt",
            "-i",
            encrypted.to_str().unwrap(),
            "-o",
            decrypted.to_str().unwrap(),
        ],
        "test",
    )
    .unwrap();

    assert!(result.status.success());
    let decrypted_content = fs::read(&decrypted).unwrap();
    assert_eq!(decrypted_content, large_content);
}
