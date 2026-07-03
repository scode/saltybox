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

    // A broken pipe means the child exited before reading all of stdin; the
    // exit status reports that failure more usefully than the write error.
    let stdin_write_error = child
        .stdin
        .as_mut()
        .expect("failed to open stdin")
        .write_all(passphrase.as_bytes())
        .err()
        .filter(|err| err.kind() != io::ErrorKind::BrokenPipe);
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

/// A known saltybox2 unit from testdata/golden-vectors-v2.json ("basic
/// text"): passphrase "test", plaintext "test payload". Duplicated here as a
/// literal so the CLI tests read as self-contained end-to-end scenarios.
const V2_FIXTURE: &str = "saltybox2:AAECAwQFBgcICQoLDA0ODwAAIAAAAAADAAAAAQABAgMEBQYHCAkKCwwNDg8QERITFBUWFwzD0jEQJtkCSl0SBslcxc9u0TKUcd-9COPdAIg";
const V2_FIXTURE_PASSPHRASE: &str = "test";
const V2_FIXTURE_PLAINTEXT: &str = "test payload";

/// Decrypting a saltybox2 file must work unconditionally — no flag or
/// environment variable involved.
#[test]
fn test_decrypt_known_v2_ciphertext() {
    let temp_dir = TempDir::new().unwrap();
    let input = temp_dir.path().join("v2.salty");
    let output = temp_dir.path().join("v2-decrypted.txt");

    fs::write(&input, V2_FIXTURE).unwrap();

    let result = run_saltybox_with_passphrase(
        &[
            "decrypt",
            "-i",
            input.to_str().unwrap(),
            "-o",
            output.to_str().unwrap(),
        ],
        V2_FIXTURE_PASSPHRASE,
    )
    .unwrap();

    assert!(
        result.status.success(),
        "v2 decrypt failed: {}",
        String::from_utf8_lossy(&result.stderr)
    );
    assert_eq!(fs::read_to_string(&output).unwrap(), V2_FIXTURE_PLAINTEXT);
}

/// update must accept a saltybox2 file on its validation read.
#[test]
fn test_update_accepts_v2_encrypted_file() {
    let temp_dir = TempDir::new().unwrap();
    let new_plain = temp_dir.path().join("new.txt");
    let encrypted = temp_dir.path().join("v2.salty");
    let decrypted = temp_dir.path().join("decrypted.txt");

    fs::write(&encrypted, V2_FIXTURE).unwrap();
    fs::write(&new_plain, "updated via v2 validation").unwrap();

    // Wrong passphrase must be caught by the v2 validation read.
    let update_args = [
        "update",
        "-i",
        new_plain.to_str().unwrap(),
        "-o",
        encrypted.to_str().unwrap(),
    ];
    let result = run_saltybox_with_passphrase(&update_args, "wrong").unwrap();
    assert!(!result.status.success());
    let stderr = String::from_utf8_lossy(&result.stderr);
    assert!(
        stderr.contains("failed to decrypt"),
        "expected authentication failure from the v2 validation read, got: {stderr}"
    );
    assert_eq!(fs::read_to_string(&encrypted).unwrap(), V2_FIXTURE);

    let result = run_saltybox_with_passphrase(&update_args, V2_FIXTURE_PASSPHRASE).unwrap();
    assert!(
        result.status.success(),
        "update over v2 file failed: {}",
        String::from_utf8_lossy(&result.stderr)
    );
    assert!(
        fs::read_to_string(&encrypted)
            .unwrap()
            .starts_with("saltybox2:")
    );

    let result = run_saltybox_with_passphrase(
        &[
            "decrypt",
            "-i",
            encrypted.to_str().unwrap(),
            "-o",
            decrypted.to_str().unwrap(),
        ],
        V2_FIXTURE_PASSPHRASE,
    )
    .unwrap();
    assert!(result.status.success());
    assert_eq!(
        fs::read_to_string(&decrypted).unwrap(),
        "updated via v2 validation"
    );
}

/// Updating a saltybox1 file rewrites it as saltybox2 — the migration path
/// for pre-existing files. The v1 input comes from the committed fixture,
/// since the CLI can no longer produce saltybox1 output.
#[test]
fn test_update_upgrades_v1_file_to_saltybox2() {
    let temp_dir = TempDir::new().unwrap();
    let new_plain = temp_dir.path().join("new.txt");
    let encrypted = temp_dir.path().join("hello.txt.salty");
    let decrypted = temp_dir.path().join("decrypted.txt");

    fs::copy(testdata_path("hello.txt.salty"), &encrypted).unwrap();
    assert!(
        fs::read_to_string(&encrypted)
            .unwrap()
            .starts_with("saltybox1:")
    );
    fs::write(&new_plain, "migrated content").unwrap();

    let result = run_saltybox_with_passphrase(
        &[
            "update",
            "-i",
            new_plain.to_str().unwrap(),
            "-o",
            encrypted.to_str().unwrap(),
        ],
        "test",
    )
    .unwrap();
    assert!(
        result.status.success(),
        "update over v1 file failed: {}",
        String::from_utf8_lossy(&result.stderr)
    );
    assert!(
        fs::read_to_string(&encrypted)
            .unwrap()
            .starts_with("saltybox2:")
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
    assert_eq!(fs::read_to_string(&decrypted).unwrap(), "migrated content");
}

/// encrypt writes the saltybox2 format.
#[test]
fn test_encrypt_writes_saltybox2() {
    let temp_dir = TempDir::new().unwrap();
    let plaintext = temp_dir.path().join("plain.txt");
    let encrypted = temp_dir.path().join("out.salty");

    fs::write(&plaintext, "format check").unwrap();

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
    assert!(
        fs::read_to_string(&encrypted)
            .unwrap()
            .starts_with("saltybox2:")
    );
}

/// Bare "saltybox2" is a proper prefix of a supported magic and must be
/// diagnosed as truncation (it was a future-version error before saltybox2
/// support existed).
#[test]
fn test_decrypt_bare_supported_magic_prefix_is_truncation_error() {
    let temp_dir = TempDir::new().unwrap();
    let input = temp_dir.path().join("truncated.salty");
    let output = temp_dir.path().join("out.txt");

    fs::write(&input, "saltybox2").unwrap();

    let result = run_saltybox_with_passphrase(
        &[
            "decrypt",
            "-i",
            input.to_str().unwrap(),
            "-o",
            output.to_str().unwrap(),
        ],
        "test",
    )
    .unwrap();

    assert!(!result.status.success());
    let stderr = String::from_utf8_lossy(&result.stderr);
    assert!(
        stderr.contains("likely truncated"),
        "expected truncation diagnostic, got: {stderr}"
    );
    assert!(!output.exists());
}

/// Versions above the supported set must get the future-version diagnostic.
#[test]
fn test_decrypt_future_version_is_unsupported_error() {
    let temp_dir = TempDir::new().unwrap();
    let input = temp_dir.path().join("future.salty");
    let output = temp_dir.path().join("out.txt");

    fs::write(&input, "saltybox3:AAAA").unwrap();

    let result = run_saltybox_with_passphrase(
        &[
            "decrypt",
            "-i",
            input.to_str().unwrap(),
            "-o",
            output.to_str().unwrap(),
        ],
        "test",
    )
    .unwrap();

    assert!(!result.status.success());
    let stderr = String::from_utf8_lossy(&result.stderr);
    assert!(
        stderr.contains("not a version we support"),
        "expected future-version diagnostic, got: {stderr}"
    );
    assert!(!output.exists());
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
