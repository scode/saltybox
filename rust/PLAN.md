# Saltybox Rust Rewrite Plan

This document outlines a step-by-step plan for rewriting
saltybox in Rust while maintaining **exact** on-disk format
compatibility and behavioral correctness (but, as indicated in
the project README, not treating the command line interface
as a stable surface)

Note: This file is mostly AI generated and is to be considered
a tool that will be deleted when the re-write is complete. It
is included in the repo for transparency purposes but does not
represent the opinion of wording of the author and may contained
unreviewed portions.

## Guiding Principles

1. **Core-to-Surface**: Build from the lowest-level crypto primitives outward
2. **Test-Driven**: Each step must have comprehensive unit tests before moving to the next
3. **Format Preservation**: The on-disk format must be byte-for-byte identical
4. **Behavioral Compatibility**: All edge cases and error handling must match the Go implementation
5. **Rust Best Practices**: Use idiomatic Rust while preserving exact behavior
6. **Preserve Go Code**: All existing Go code remains untouched during the rewrite for comparison and cross-testing

## Cryptographic Library Choice

**Decision**: Use RustCrypto's `crypto_secretbox` for XSalsa20Poly1305 encryption.

**Rationale**:

- Pure Rust implementation from the RustCrypto ecosystem
- Part of the nacl-compat repository, designed for NaCl API compatibility
- Implements XSalsa20Poly1305 AEAD (Authenticated Encryption with Associated Data)
- Provides the exact cryptographic primitive we need (symmetric encryption)
- Active maintenance within the RustCrypto organization
- Compatible with NaCl/libsodium implementations

**Crate**: `crypto_secretbox = "0.1"` from https://github.com/RustCrypto/nacl-compat

## Code Coexistence Strategy

**IMPORTANT**: The Rust rewrite will be developed **alongside** the existing Go implementation, not as a replacement of the code. This means:

- **All Go code stays in place** throughout the entire rewrite process
- Rust code will live in a separate directory structure (not replacing Go files)
- Both implementations will coexist in the same repository
- We can cross-test: encrypt with Go, decrypt with Rust and vice versa
- Go implementation serves as the reference implementation during development
- **No Go code deletion until the very end** (if ever - see "Post-Rewrite: Deprecation Strategy")

This approach provides:

- A stable reference for behavioral comparison
- Ability to run both implementations side-by-side
- Safety net during development
- Confidence in format compatibility through cross-testing

## Step 1: Project Setup [DONE]

### Implementation Tasks

- Initialize Cargo project with workspace structure **in a separate rust/ directory**
- Set up dependencies:
  - `scrypt` (for key derivation)
  - `crypto_secretbox` (RustCrypto's XSalsa20Poly1305 implementation)
  - `base64` (for armoring)
  - `rand` (for random salt/nonce generation)
  - `anyhow` or `thiserror` (for error handling)
  - `clap` v4 (for CLI, added later)
- Set up CI/build configuration
- Create basic module structure:

  ```
  rust/                    # New Rust implementation (separate from Go)
    Cargo.toml
    src/
      lib.rs               # Library entry point
      crypto/              # Core encryption (Step 2)
      armor/               # Armoring layer (Step 3)
      passphrase/          # Passphrase reading (Step 4)
      cli/                 # CLI (Step 5)
      bin/
        saltybox.rs        # Main CLI binary
        golden.rs          # Golden vector tool

  # Existing Go code remains untouched:
  # ├── commands/
  # ├── golden/
  # ├── preader/
  # ├── secretcrypt/
  # ├── varmor/
  # ├── saltybox.go
  # └── ...
  ```

### Testing Considerations

- Ensure project builds
- Basic "hello world" sanity test
- Verify Go code still builds and tests pass

### Key Notes

- Use a workspace to separate library from binaries (main CLI + golden tool)
- Set MSRV (Minimum Supported Rust Version) to align with current stable
- **Do NOT modify or delete any Go files**
- Rust implementation lives entirely in `rust/` directory
- Can symlink or copy `testdata/golden-vectors.json` for shared test data

---

## Step 2: Core Encryption Layer (secretcrypt) [TODO]

### Implementation Tasks

Implement the core encryption/decryption in `src/crypto/mod.rs`:

1. **Constants** (secretcrypt/secretcrypt.go:19-33):
   - `SALT_LEN = 8`
   - `NONCE_LEN = 24`
   - `KEY_LEN = 32`
   - scrypt parameters: `N = 32768, r = 8, p = 1`

2. **Key Derivation**:

   ```rust
   fn derive_key(passphrase: &str, salt: &[u8; 8]) -> Result<[u8; 32]>
   ```

   - Use `scrypt::scrypt()` with exact parameters from Go code
   - Input: passphrase as UTF-8 string, 8-byte salt
   - Output: 32-byte key

3. **Encryption**:

   ```rust
   fn encrypt(passphrase: &str, plaintext: &[u8]) -> Result<Vec<u8>>
   fn encrypt_deterministic(
       passphrase: &str,
       plaintext: &[u8],
       salt: &[u8; 8],
       nonce: &[u8; 24]
   ) -> Result<Vec<u8>>
   ```

   - Generate random 8-byte salt
   - Generate random 24-byte nonce
   - Derive key using scrypt
   - Encrypt using crypto_secretbox's XSalsa20Poly1305
   - Use `XSalsa20Poly1305::new()` with the 32-byte key
   - Use the AEAD `encrypt()` method with nonce and plaintext
   - Binary format: `salt(8) + nonce(24) + length(8) + sealedbox(variable)`
   - Length field: **big-endian signed 64-bit integer** (i64)
   - The sealed box includes the Poly1305 MAC (16 bytes overhead)

4. **Decryption**:
   ```rust
   fn decrypt(passphrase: &str, ciphertext: &[u8]) -> Result<Vec<u8>>
   ```

   - Read salt (8 bytes)
   - Read nonce (24 bytes)
   - Read length (8 bytes, big-endian i64)
   - Validate length (see edge cases below)
   - Read sealed box (length bytes)
   - Derive key using scrypt
   - Decrypt and authenticate using crypto_secretbox's XSalsa20Poly1305
   - Use `XSalsa20Poly1305::new()` with the 32-byte key
   - Use the AEAD `decrypt()` method with nonce and ciphertext

### Critical Edge Cases & Behaviors

**From secretcrypt_test.go and secretcrypt.go:**

1. **Empty Plaintext** (secretcrypt.go:186-188):
   - Empty plaintext must round-trip correctly
   - Decryption of empty plaintext returns `[]` (empty vec), not null

2. **Length Validation** (secretcrypt.go:146-155):
   - Length must be non-negative (reject negative i64)
   - Length must not exceed max platform `isize` (if applicable)
   - Length must not exceed available input data
   - Error: "negative sealed box length"
   - Error: "sealed box length exceeds max int" (if platform-specific)
   - Error: "truncated or corrupt input; claimed length greater than available input"

3. **Trailing Data Validation** (secretcrypt.go:167-169):
   - **CRITICAL**: After reading the sealed box, verify no trailing bytes remain
   - Must reject any extra data after the sealed box
   - Error: "invalid input: unexpected data after sealed box"

4. **Truncation Detection** (secretcrypt.go:125-140):
   - Detect truncated salt: "input likely truncated while reading salt"
   - Detect truncated nonce: "input likely truncated while reading nonce"
   - Detect truncated length: "input likely truncated while reading sealed box"
   - Detect truncated sealed box: "truncated or corrupt input (while reading sealed box)"

5. **Authentication Failure** (secretcrypt.go:182-184):
   - NaCl secretbox authentication failure (wrong passphrase, corrupted data, etc.)
   - Error: "corrupt input, tampered-with data, or bad passphrase"

### Testing Requirements

**Unit Tests** (based on secretcrypt_test.go):

1. **Round-trip tests**:
   - Empty plaintext
   - Small plaintext (5 bytes)
   - Medium plaintext (64KB)
   - Large plaintext (128KB)
   - All zero bytes (various lengths)
   - All 0xFF bytes (various lengths)
   - All byte values 0-255

2. **Deterministic encryption test**:
   - Same salt/nonce produces identical ciphertext
   - Different nonce produces different ciphertext
   - Both decrypt to same plaintext

3. **Length validation tests**:
   - Negative length (craft invalid ciphertext)
   - Length exceeding available data
   - Length exceeding platform max (if applicable)

4. **Trailing data test**:
   - Valid ciphertext + junk data → must fail
   - Error message must contain "unexpected data after sealed box"

5. **Truncation tests**:
   - Truncate in salt → error
   - Truncate in nonce → error
   - Truncate in length → error
   - Truncate in sealed box → error

6. **Bad passphrase test**:
   - Encrypt with one passphrase, decrypt with another → error

### Dependencies

- `scrypt` crate for key derivation (e.g., `scrypt = "0.11"`)
- `crypto_secretbox` from RustCrypto nacl-compat (e.g., `crypto_secretbox = "0.1"`)
  - Provides XSalsa20Poly1305 AEAD cipher
  - Implements the NaCl secretbox primitive
- `rand` for random salt/nonce generation (e.g., `rand = "0.8"`)
- Standard library for big-endian i64 encoding/decoding (no external dep needed)

**Note on crypto_secretbox**: Part of RustCrypto's nacl-compat repository, implements
XSalsa20Poly1305 authenticated encryption matching the NaCl specification.

---

## Step 3: Armoring Layer (varmor) [TODO]

### Implementation Tasks

Implement versioned armoring in `src/armor/mod.rs`:

1. **Constants** (varmor/varmor.go:14-17):
   - `MAGIC_PREFIX = "saltybox"`
   - `V1_MAGIC = "saltybox1:"`

2. **Wrap Function**:

   ```rust
   fn wrap(body: &[u8]) -> String
   ```

   - Encode body using base64 URL-safe encoding (RFC 4648 Section 5)
   - **No padding** (RawURLEncoding in Go)
   - Prepend "saltybox1:" magic
   - Return format: `saltybox1:{base64url-no-padding}`

3. **Unwrap Function**:
   ```rust
   fn unwrap(armored: &str) -> Result<Vec<u8>>
   ```

   - Check minimum length (>= length of "saltybox1:")
   - Check for "saltybox1:" prefix → decode and return
   - Check for "saltybox" prefix (but not v1) → error: unsupported version
   - Otherwise → error: not saltybox data

### Critical Edge Cases & Behaviors

**From varmor.go and varmor_test.go:**

1. **Truncation Detection** (varmor.go:35-37):
   - Input shorter than magic marker
   - Error: "input size smaller than magic marker; likely truncated"

2. **Version Handling** (varmor.go:47-48):
   - Future versions (e.g., "saltybox2:", "saltybox999:")
   - Error: "input claims to be saltybox, but not a version we support"

3. **Format Recognition** (varmor.go:49-50):
   - Input that doesn't start with "saltybox"
   - Error: "input unrecognized as saltybox data"

4. **Base64 Decoding Errors** (varmor.go:43-45):
   - Invalid base64 characters
   - Error: "base64 decoding failed: {underlying error}"

5. **Exact Encoding** (varmor_test.go:63-65):
   - All byte values 0-255 must encode to specific expected string
   - Use URL-safe alphabet: `-` and `_` instead of `+` and `/`
   - No padding characters (`=`)

### Testing Requirements

**Unit Tests** (based on varmor_test.go):

1. **Round-trip tests**:
   - Empty bytes
   - Simple string "test"
   - Large random data (100KB)
   - All byte values 0-255

2. **Exact encoding test**:
   - Verify that bytes [0..255] produce the exact expected base64url string
   - Reference from varmor_test.go:64

3. **Error cases**:
   - Empty string → truncated error
   - "saltybox999:..." → unsupported version
   - "not saltybox data" → unrecognized
   - "saltybox1:bad$$" → base64 decode error

4. **Whitespace handling**:
   - Verify output contains no whitespace/newlines
   - Verify input with whitespace is rejected

### Dependencies

- `base64` crate with URL-safe, no-padding configuration

---

## Step 4: Passphrase Reading [TODO]

### Implementation Tasks

Implement passphrase reading in `src/passphrase/mod.rs`:

1. **PassphraseReader Trait**:

   ```rust
   trait PassphraseReader {
       fn read_passphrase(&mut self) -> Result<String>;
   }
   ```

2. **Terminal Reader** (preader.go:40-58):

   ```rust
   struct TerminalPassphraseReader;
   ```

   - Check if stdin is a terminal (use `atty` or `is_terminal()`)
   - Write prompt to stderr: "Passphrase (saltybox): "
   - Read password from stdin without echo (use `rpassword` crate)
   - Error if stdin is not a terminal

3. **Caching Reader** (preader.go:60-81):

   ```rust
   struct CachingPassphraseReader<R: PassphraseReader> {
       upstream: R,
       cached: Option<String>,
   }
   ```

   - Lazy evaluation: only call upstream on first read
   - Cache and return same value on subsequent reads

4. **Constant Reader** (preader.go:32-38):

   ```rust
   struct ConstantPassphraseReader {
       passphrase: String,
   }
   ```

   - For testing: always returns the same passphrase

5. **Reader-based Reader** (preader.go:83-94):
   ```rust
   struct ReaderPassphraseReader<R: Read> {
       reader: R,
   }
   ```

   - Reads all data from the provided reader
   - Used for testing and potentially piped input

### Critical Edge Cases & Behaviors

**From preader.go:**

1. **Terminal Detection** (preader.go:44-46):
   - Must check `os.Stdin.Fd()` is a terminal
   - Error: "cannot read passphrase from terminal - stdin is not a terminal"

2. **Prompt to stderr** (preader.go:48):
   - Prompt written to stderr, not stdout
   - Allows output redirection without capturing prompt

3. **Caching Semantics** (preader.go:70-80):
   - "At most once" semantics
   - Lazy - first call triggers upstream read
   - Subsequent calls return cached value without calling upstream
   - Errors on first read propagate, but don't get cached

### Testing Requirements

1. **Constant reader**: Simple pass-through test
2. **Reader-based reader**: Read from string/bytes
3. **Caching reader**:
   - Verify upstream called only once
   - Verify same value returned on multiple calls
4. **Terminal reader**: Mock/integration test if feasible

### Dependencies

- `rpassword` for reading passwords without echo
- `atty` or std `is_terminal()` for terminal detection

---

## Step 5: Golden Test Vector Validation [TODO]

### Implementation Tasks

Before building the full CLI, validate correctness against golden vectors:

1. **Load Golden Vectors**:
   - Read `testdata/golden-vectors.json`
   - Deserialize using `serde_json`
   - Structure matches Go's `goldenVector` (golden/main.go:51-58)

2. **Validate Each Vector**:
   - Base64-decode plaintext, passphrase
   - Unwrap (unarmor) ciphertext
   - Decrypt with passphrase
   - Compare decrypted output with expected plaintext
   - Report pass/fail for each test

3. **Generate Golden Vectors** (optional, but recommended):
   - Port the generation logic from golden/main.go:76-247
   - Ensures Rust implementation can both read and write the format
   - Compare generated output against existing golden-vectors.json

### Critical Behaviors

**From golden/main.go:**

1. **Test Coverage** (lines 103-221):
   - Empty plaintext
   - Single byte
   - UTF-8 multibyte characters
   - All zero bytes
   - All 0xFF bytes
   - Large data (10KB)
   - Empty passphrase
   - Very long passphrase (1000 bytes, 10KB)
   - Special characters in passphrase
   - All byte values 0-255 in plaintext, passphrase, salt, nonce
   - Zero and 0xFF salts/nonces
   - Newlines in plaintext
   - Plaintext resembling format header ("saltybox1:fakedata")

2. **Deterministic Encryption** (golden/main.go:64-73):
   - Use `encrypt_deterministic()` with fixed salt/nonce
   - Allows reproducible test vectors

3. **Error Reporting** (golden/main.go:262-299):
   - Report which test failed
   - Show test number and comment
   - Show expected vs actual lengths on mismatch
   - Return error if any test fails

### Testing Requirements

1. **Validation test**:
   - All existing golden vectors must pass
   - **This is the primary correctness check**
   - Run with: `cargo test --test golden_vectors`

2. **Generation test** (if implemented):
   - Generated vectors should match existing golden-vectors.json
   - Or at minimum, round-trip correctly

3. **Cross-Implementation Testing** (leveraging coexisting Go code):
   - Encrypt with Go CLI, decrypt with Rust implementation
   - Encrypt with Rust implementation, decrypt with Go CLI
   - Use actual files (not just test vectors)
   - Verify byte-for-byte identical output when using same salt/nonce
   - This validates real-world compatibility, not just test vectors

### Dependencies

- `serde` + `serde_json` for JSON parsing
- Existing `testdata/golden-vectors.json` from Go implementation
- Go implementation (still present in codebase) for cross-testing

### Key Notes

- **This step is critical** - it validates that the Rust implementation is byte-for-byte compatible
- All 63+ test vectors must pass before proceeding
- Consider running this as a separate integration test
- Cross-implementation testing is only possible because we kept the Go code!

---

## Step 6: File Operations Module [TODO]

### Implementation Tasks

Implement file encryption/decryption operations in `src/file_ops/mod.rs`:

1. **Encrypt File Function**:

   ```rust
   fn encrypt_file(
       input_path: &Path,
       output_path: &Path,
       passphrase_reader: &mut dyn PassphraseReader
   ) -> Result<()>
   ```

   - Read plaintext from input file
   - Read passphrase from reader
   - Encrypt using crypto layer
   - Wrap using armor layer
   - Write to output file with mode 0o600

2. **Decrypt File Function**:

   ```rust
   fn decrypt_file(
       input_path: &Path,
       output_path: &Path,
       passphrase_reader: &mut dyn PassphraseReader
   ) -> Result<()>
   ```

   - Read armored ciphertext from input file
   - Read passphrase from reader
   - Unwrap using armor layer
   - Decrypt using crypto layer
   - Write to output file with mode 0o600

3. **Update File Function**:
   ```rust
   fn update_file(
       plain_path: &Path,
       crypt_path: &Path,
       passphrase_reader: &mut dyn PassphraseReader
   ) -> Result<()>
   ```

   - Read existing encrypted file
   - Read passphrase (cached)
   - Decrypt to validate passphrase (discard result)
   - Read new plaintext
   - Encrypt with same passphrase
   - Write atomically (tempfile + fsync + rename)

### Critical Edge Cases & Behaviors

**From commands/commands.go:**

1. **File Permissions** (commands.go:39, 76):
   - Output files must be created with mode 0o600
   - Restrictive permissions for security

2. **Update Atomicity** (commands.go:104-152):
   - Write to temp file in same directory
   - Fsync temp file before rename
   - Rename temp file to target (atomic on POSIX)
   - Clean up temp file on error (defer)
   - Ensures no corruption: either old file or new file, never partial

3. **Passphrase Validation** (commands.go:95-102):
   - Decrypt existing file first (validate passphrase)
   - Discard decrypted plaintext (not needed)
   - Use caching reader to avoid re-prompting
   - Prevents accidental passphrase changes

4. **Error Handling** (throughout):
   - Wrap errors with context (file paths, operation names)
   - Example: "failed to read from {path}: {error}"
   - Example: "failed to decrypt: {error}"

### Testing Requirements

1. **Encrypt/decrypt round-trip**:
   - Create temp file with plaintext
   - Encrypt to temp output
   - Decrypt back
   - Verify plaintext matches

2. **Update operation**:
   - Encrypt file with passphrase
   - Update with new plaintext, same passphrase
   - Verify new content decrypts correctly
   - Verify wrong passphrase is rejected

3. **File permissions**:
   - Verify output file has mode 0o600
   - Platform-specific (Unix-like systems)

4. **Atomic update**:
   - Simulate error during update
   - Verify original file intact
   - Verify no temp file left behind

5. **Error cases**:
   - Non-existent input file
   - Permission denied on output
   - Disk full scenarios (if feasible)

### Dependencies

- `std::fs` for file I/O
- `tempfile` for atomic updates
- Platform-specific APIs for fsync (use `std::os::unix::fs::OpenOptionsExt`)

---

## Step 7: CLI with Clap [TODO]

### Implementation Tasks

Implement modern CLI using Clap v4 in `src/main.rs`:

1. **CLI Structure**:

   ```rust
   #[derive(Parser)]
   struct Cli {
       #[command(subcommand)]
       command: Command,
   }

   #[derive(Subcommand)]
   enum Command {
       Encrypt(EncryptArgs),
       Decrypt(DecryptArgs),
       Update(UpdateArgs),
   }
   ```

2. **Encrypt Subcommand**:

   ```rust
   #[derive(Args)]
   struct EncryptArgs {
       #[arg(short = 'i', long, value_name = "FILE")]
       input: PathBuf,

       #[arg(short = 'o', long, value_name = "FILE")]
       output: PathBuf,
   }
   ```

   - Read plaintext from input file
   - Write armored ciphertext to output file
   - Prompt for passphrase interactively

3. **Decrypt Subcommand**:

   ```rust
   #[derive(Args)]
   struct DecryptArgs {
       #[arg(short = 'i', long, value_name = "FILE")]
       input: PathBuf,

       #[arg(short = 'o', long, value_name = "FILE")]
       output: PathBuf,
   }
   ```

   - Read armored ciphertext from input file
   - Write plaintext to output file
   - Prompt for passphrase interactively

4. **Update Subcommand**:

   ```rust
   #[derive(Args)]
   struct UpdateArgs {
       #[arg(short = 'i', long, value_name = "FILE")]
       input: PathBuf,

       #[arg(short = 'o', long, value_name = "FILE")]
       output: PathBuf,
   }
   ```

   - Read new plaintext from input file
   - Read existing encrypted file from output path
   - Validate passphrase, then encrypt new content
   - Write atomically to output path

5. **Error Handling**:
   - Use `anyhow::Result` for error propagation
   - Pretty-print errors with context
   - Exit with non-zero code on error

### CLI Design Notes

**Differences from Go CLI:**

The Go CLI uses flags like:

```
saltybox encrypt -i input.txt -o output.txt.saltybox
```

The new Rust CLI will use modern subcommands:

```
saltybox encrypt --input input.txt --output output.txt.saltybox
saltybox decrypt -i input.txt.saltybox -o output.txt
saltybox update -i new.txt -o existing.txt.saltybox
```

- Short flags: `-i`, `-o` (compatible with Go)
- Long flags: `--input`, `--output` (more explicit)
- Subcommands are required (no positional commands)
- Help is automatic via Clap

### Testing Requirements

1. **Integration tests**:
   - Test encrypt command end-to-end
   - Test decrypt command end-to-end
   - Test update command end-to-end

2. **Error handling**:
   - Missing required arguments → helpful error
   - Non-existent input file → clear error message
   - Wrong passphrase → clear error message

3. **Help text**:
   - `saltybox --help` shows overview
   - `saltybox encrypt --help` shows encrypt options
   - Verify help is clear and useful

### Dependencies

- `clap` v4 with `derive` feature
- `anyhow` for error handling

---

## Step 8: Golden Test Tool (Optional) [TODO]

### Implementation Tasks

Create a separate binary for golden vector generation/validation:

1. **Binary Setup**:
   - Add `[[bin]]` section in Cargo.toml
   - Name: `golden`
   - Path: `src/bin/golden.rs`

2. **CLI Structure**:

   ```rust
   #[derive(Parser)]
   struct Cli {
       #[command(subcommand)]
       command: Command,
   }

   #[derive(Subcommand)]
   enum Command {
       Generate,
       Validate,
   }
   ```

3. **Generate Command**:
   - Port logic from golden/main.go:76-247
   - Create all test vectors with deterministic encryption
   - Write to `testdata/golden-vectors.json`
   - Sort by ciphertext for stability

4. **Validate Command**:
   - Port logic from golden/main.go:249-307
   - Load vectors from `testdata/golden-vectors.json`
   - Decrypt each and compare with expected plaintext
   - Report pass/fail counts

### Testing Requirements

- Generate command produces valid JSON
- Validate command passes all tests
- Generated vectors match existing golden-vectors.json (if ported exactly)

### Dependencies

- Same as main CLI
- `serde_json` for JSON I/O

### Key Notes

- This can be part of Step 5 or done separately
- Useful for debugging format compatibility issues

---

## Step 9: Documentation & Polish [TODO]

### Implementation Tasks

1. **README.md**:
   - Update installation instructions (Cargo instead of Go)
   - Update usage examples (new CLI syntax)
   - Note Rust implementation status
   - Link to Go version for historical reference

2. **Code Documentation**:
   - Add rustdoc comments to public APIs
   - Document safety considerations
   - Document format compatibility guarantees

3. **Testing**:
   - Run `cargo test` - all tests pass
   - Run `cargo clippy` - no warnings
   - Run `cargo fmt` - consistent formatting
   - Test on multiple platforms (Linux, macOS, Windows if supported)

4. **CI/CD**:
   - Set up GitHub Actions or similar
   - Run tests on every commit
   - Build binaries for releases

5. **Migration Guide**:
   - Document CLI differences
   - Note that files are fully compatible
   - Provide examples of equivalent commands

### Testing Requirements

1. **Cross-platform testing**:
   - Linux (primary platform)
   - macOS
   - Windows (if feasible)

2. **Interoperability testing**:
   - Encrypt with Go, decrypt with Rust
   - Encrypt with Rust, decrypt with Go
   - All golden vectors pass in both directions

3. **Performance testing** (optional):
   - Benchmark key derivation
   - Benchmark encryption/decryption
   - Compare with Go implementation

### Key Notes

- The Rust version should be a drop-in replacement for file format purposes
- CLI changes are acceptable (documented differences)
- Maintain same format guarantees: "future versions will decrypt older data"

---

## Risk Mitigation & Validation Strategy

### Format Compatibility Validation

1. **Golden Test Vectors** (Step 5):
   - Primary validation mechanism
   - 63+ test cases covering edge cases
   - Must pass 100% before claiming compatibility

2. **Cross-Implementation Testing** (enabled by keeping Go code):
   - Encrypt with Go implementation, decrypt with Rust
   - Encrypt with Rust implementation, decrypt with Go
   - Test with real-world files
   - This is a key advantage of maintaining both implementations side-by-side

3. **Byte-Level Inspection**:
   - Compare encrypted output byte-by-byte
   - Verify salt, nonce, length field, sealed box are identical

### Testing Levels

1. **Unit Tests** (each step):
   - Test individual functions in isolation
   - Cover edge cases and error conditions
   - Fast, run frequently during development

2. **Integration Tests** (Steps 5, 6, 7):
   - Test components working together
   - File I/O, CLI, end-to-end flows
   - Slower, run before commits

3. **Compatibility Tests** (Step 5, 9):
   - Golden vectors
   - Cross-implementation verification
   - Critical for correctness

### Code Review Focus Areas

1. **Crypto Implementation** (Step 2):
   - Verify scrypt parameters exact
   - Verify NaCl secretbox usage correct
   - Verify binary format byte-for-byte
   - Check endianness of length field (big-endian)

2. **Error Handling** (all steps):
   - All error conditions from Go code covered
   - Error messages helpful and consistent
   - No panics in normal error cases

3. **Edge Cases** (all steps):
   - Empty plaintext
   - Zero/max byte values
   - Truncation detection
   - Trailing data rejection
   - Platform-specific issues (if any)

---

## Success Criteria

Before considering the rewrite complete:

- [ ] All golden test vectors pass (63+)
- [ ] All unit tests pass
- [ ] All integration tests pass
- [ ] Clippy reports no warnings
- [ ] Documentation complete
- [ ] Cross-implementation testing successful
- [ ] CLI functional and user-friendly
- [ ] Performance acceptable (comparable to Go)

---

## Notes on Behavioral Preservation

### String Encoding

- Passphrases are UTF-8 strings in both Go and Rust
- File paths use platform conventions
- Armored output is ASCII (base64url subset)

### Binary Format

- Salt: 8 bytes, random
- Nonce: 24 bytes, random
- Length: 8 bytes, **big-endian signed int64**
- Sealed box: variable length, includes 16-byte Poly1305 MAC

### Error Behavior

- Must match Go error messages where practical
- Distinguish truncation, corruption, bad passphrase, format errors
- Provide actionable error messages

### Platform Considerations

- File permissions (0o600) are Unix-specific
- Atomic rename is POSIX, may need special handling on Windows
- Terminal detection works differently on Windows
- Test on target platforms

---

## Post-Rewrite: Deprecation Strategy (Far Future - Optional)

**NOTE**: This section describes a _potential_ future deprecation strategy. It is **NOT** part of the rewrite process itself. The Go code will remain in the repository throughout the rewrite and likely for years afterward (if not indefinitely).

Once Rust implementation is stable and battle-tested:

1. Mark Go implementation as maintenance mode
2. Encourage new users to use Rust version
3. Maintain Go version for legacy users
4. Keep both implementations passing golden vectors
5. Consider archiving Go version only after years of Rust stability
6. **Or keep both indefinitely** - having two independent implementations is a security advantage

This ensures a smooth transition while maintaining trust in the format.

**During the rewrite**: Both implementations coexist. **No Go code is deleted**.
