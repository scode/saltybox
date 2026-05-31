//! CLI integration tests
//!
//! Tests the command-line interface end-to-end.

use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use tempfile::TempDir;

/// Get path to the saltybox binary
fn saltybox_bin() -> &'static Path {
    Path::new(env!("CARGO_BIN_EXE_saltybox"))
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

    let stdin_write_error = {
        let stdin = child.stdin.as_mut().expect("failed to open stdin");
        if let Err(err) = stdin.write_all(passphrase.as_bytes()) {
            if err.kind() != io::ErrorKind::BrokenPipe {
                Some(err)
            } else {
                None
            }
        } else {
            None
        }
    };
    drop(child.stdin.take());

    let output = child.wait_with_output();
    if let Some(err) = stdin_write_error {
        output?;
        return Err(err);
    }
    output
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

/// Exercises output paths such as `out.salty` that have no directory component.
///
/// `Path::parent()` reports these as having an empty parent path. The CLI still
/// needs to treat them as files in the child process's current directory.
#[test]
fn test_output_path_without_directory_component_roundtrip() {
    let temp_dir = TempDir::new().unwrap();
    let plaintext = temp_dir.path().join("plain.txt");

    fs::write(&plaintext, "bare relative output").unwrap();

    let mut child = Command::new(saltybox_bin())
        .arg("--passphrase-stdin")
        .args([
            "encrypt",
            "-i",
            plaintext.to_str().unwrap(),
            "-o",
            "out.salty",
        ])
        .current_dir(temp_dir.path())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child.stdin.as_mut().unwrap().write_all(b"test").unwrap();
    let result = child.wait_with_output().unwrap();
    assert!(
        result.status.success(),
        "encrypt failed: {}",
        String::from_utf8_lossy(&result.stderr)
    );

    let mut child = Command::new(saltybox_bin())
        .arg("--passphrase-stdin")
        .args(["decrypt", "-i", "out.salty", "-o", "decrypted.txt"])
        .current_dir(temp_dir.path())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child.stdin.as_mut().unwrap().write_all(b"test").unwrap();
    let result = child.wait_with_output().unwrap();
    assert!(
        result.status.success(),
        "decrypt failed: {}",
        String::from_utf8_lossy(&result.stderr)
    );

    assert_eq!(
        fs::read_to_string(temp_dir.path().join("decrypted.txt")).unwrap(),
        "bare relative output"
    );
}

#[test]
fn test_passphrase_stdin_preserves_trailing_newline() {
    let temp_dir = TempDir::new().unwrap();
    let plaintext = temp_dir.path().join("plaintext.txt");
    let encrypted = temp_dir.path().join("encrypted.txt.salty");
    let decrypted = temp_dir.path().join("decrypted.txt");

    fs::write(&plaintext, "newline-sensitive passphrase").unwrap();

    let result = run_saltybox_with_passphrase(
        &[
            "encrypt",
            "-i",
            plaintext.to_str().unwrap(),
            "-o",
            encrypted.to_str().unwrap(),
        ],
        "test\n",
    )
    .unwrap();
    assert!(
        result.status.success(),
        "encrypt failed: {}",
        String::from_utf8_lossy(&result.stderr)
    );

    let decrypt_args = [
        "decrypt",
        "-i",
        encrypted.to_str().unwrap(),
        "-o",
        decrypted.to_str().unwrap(),
    ];

    let result = run_saltybox_with_passphrase(&decrypt_args, "test").unwrap();
    assert!(!result.status.success());
    assert!(!decrypted.exists());

    let result = run_saltybox_with_passphrase(&decrypt_args, "test\n").unwrap();
    assert!(
        result.status.success(),
        "decrypt failed: {}",
        String::from_utf8_lossy(&result.stderr)
    );

    assert_eq!(
        fs::read_to_string(&decrypted).unwrap(),
        "newline-sensitive passphrase"
    );
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
fn test_command_aliases() {
    let temp_dir = TempDir::new().unwrap();
    let plaintext = temp_dir.path().join("plaintext.txt");
    let encrypted = temp_dir.path().join("encrypted.txt.salty");
    let decrypted = temp_dir.path().join("decrypted.txt");

    fs::write(&plaintext, "Original content").unwrap();

    let result = run_saltybox_with_passphrase(
        &[
            "e",
            "-i",
            plaintext.to_str().unwrap(),
            "-o",
            encrypted.to_str().unwrap(),
        ],
        "test",
    )
    .unwrap();
    assert!(
        result.status.success(),
        "encrypt alias failed: {}",
        String::from_utf8_lossy(&result.stderr)
    );

    fs::write(&plaintext, "Updated content").unwrap();

    let update_args = [
        "u",
        "-i",
        plaintext.to_str().unwrap(),
        "-o",
        encrypted.to_str().unwrap(),
    ];

    let result = run_saltybox_with_passphrase(&update_args, "wrong").unwrap();
    assert!(!result.status.success());

    let decrypt_args = [
        "d",
        "-i",
        encrypted.to_str().unwrap(),
        "-o",
        decrypted.to_str().unwrap(),
    ];

    let result = run_saltybox_with_passphrase(&decrypt_args, "test").unwrap();
    assert!(
        result.status.success(),
        "decrypt alias after failed update alias failed: {}",
        String::from_utf8_lossy(&result.stderr)
    );
    assert_eq!(fs::read_to_string(&decrypted).unwrap(), "Original content");

    let result = run_saltybox_with_passphrase(&update_args, "test").unwrap();
    assert!(
        result.status.success(),
        "update alias failed: {}",
        String::from_utf8_lossy(&result.stderr)
    );

    let result = run_saltybox_with_passphrase(&decrypt_args, "test").unwrap();
    assert!(
        result.status.success(),
        "decrypt alias failed: {}",
        String::from_utf8_lossy(&result.stderr)
    );

    assert_eq!(fs::read_to_string(&decrypted).unwrap(), "Updated content");
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

    let decrypted = temp_dir.path().join("decrypted.txt");
    let result = run_saltybox_with_passphrase(
        &[
            "decrypt",
            "-i",
            encrypted.to_str().unwrap(),
            "-o",
            decrypted.to_str().unwrap(),
        ],
        "correct_password",
    )
    .unwrap();
    assert!(
        result.status.success(),
        "decrypt after failed update failed: {}",
        String::from_utf8_lossy(&result.stderr)
    );

    let decrypted_content = fs::read_to_string(&decrypted).unwrap();
    assert_eq!(decrypted_content, "Original");
}

#[test]
fn test_update_identical_input_output_fails() {
    let temp_dir = TempDir::new().unwrap();
    let plaintext = temp_dir.path().join("plaintext.txt");
    let encrypted = temp_dir.path().join("encrypted.txt.salty");
    let decrypted = temp_dir.path().join("decrypted.txt");

    fs::write(&plaintext, "Original content").unwrap();

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
            "update",
            "-i",
            encrypted.to_str().unwrap(),
            "-o",
            encrypted.to_str().unwrap(),
        ],
        "test",
    )
    .unwrap();

    assert!(!result.status.success());
    let stderr = String::from_utf8_lossy(&result.stderr);
    assert!(
        stderr.contains("input and output paths must be different for update"),
        "Expected same-path update rejection, got: {}",
        stderr
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
    assert_eq!(decrypted_content, "Original content");
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
