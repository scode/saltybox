//! File encryption/decryption operations
//!
//! This module provides high-level file operations for encrypting, decrypting,
//! and updating files using the saltybox format.

use crate::error::{ErrorCategory, ErrorKind, Result, SaltyboxError};
use crate::format;
use crate::passphrase::PassphraseReader;
use std::fs;
use std::io::{self, Read, Write};
use std::path::Path;
#[cfg(not(any(target_os = "linux", target_os = "macos")))]
use std::path::PathBuf;
use tempfile::NamedTempFile;
use zeroize::Zeroizing;

#[cfg(any(target_os = "linux", target_os = "macos"))]
mod output_path;
#[cfg(any(target_os = "linux", target_os = "macos"))]
use output_path::OutputDestination;

const TEMPFILE_PREFIX: &str = ".saltybox-";
const TEMPFILE_SUFFIX: &str = ".tmp";

/// Reads the passphrase and rejects one that is empty or contains a line
/// break.
///
/// Both are refused for all operations, because both are almost always an
/// accident when piping to `--passphrase-stdin` rather than intent. The
/// canonical cases are `echo -n "$PASS"` with `PASS` unset, which sends zero
/// bytes, and `echo "$PASS"` without `-n`, which appends a newline (and with
/// `PASS` unset sends nothing else). Either would otherwise silently produce
/// a file protected by nothing, or by a passphrase the user does not know
/// they chose. A line break is `\n` or `\r`, so Windows-style `\r\n` endings
/// are caught too. Line breaks are rejected anywhere, not just at the end:
/// piped input is meant to be a single-line passphrase, and feeding arbitrary
/// bytes is left to a possible future option that reads the passphrase from
/// a file.
///
/// The checks live here at the operation layer, not in the individual
/// [`PassphraseReader`] implementations, so they hold regardless of how the
/// passphrase was obtained.
fn read_valid_passphrase(reader: &mut dyn PassphraseReader) -> Result<Zeroizing<Vec<u8>>> {
    let passphrase = reader.read_passphrase()?;
    if passphrase.is_empty() {
        return Err(SaltyboxError::with_kind(
            ErrorCategory::User,
            ErrorKind::EmptyPassphrase,
            "empty passphrase is not allowed (note that an unset shell variable expands to empty)",
        ));
    }
    if passphrase.iter().any(|b| matches!(b, b'\n' | b'\r')) {
        return Err(SaltyboxError::with_kind(
            ErrorCategory::User,
            ErrorKind::PassphraseContainsLineBreak,
            "passphrase containing a line break is not allowed (when piping to --passphrase-stdin, use `echo -n` or `printf '%s' \"$PASS\"`)",
        ));
    }
    Ok(passphrase)
}

/// Encrypt a file with a passphrase
///
/// Reads plaintext from `input_path`, encrypts it using a passphrase from
/// `passphrase_reader`, and writes the armored ciphertext to `output_path`.
/// If the reader offers a confirmation (see
/// [`PassphraseReader::read_confirmation`]), a confirmation that differs from
/// the passphrase fails the call as a user error before anything is written.
///
/// Which format is written is the caller's choice via `write_engine`; the
/// CLI always passes [`format::default_write_engine`].
///
/// Output is written atomically via a same-directory temporary file. A
/// symlinked `output_path` is followed and the file it ultimately points to
/// is replaced; the temporary file goes in that file's directory.
/// On Unix systems, the final file mode is set to 0o600 (read/write for owner only).
pub fn encrypt_file(
    input_path: &Path,
    output_path: &Path,
    passphrase_reader: &mut dyn PassphraseReader,
    write_engine: &dyn format::FormatEngine,
) -> Result<()> {
    check_output_path(output_path)?;
    let output = OutputDestination::resolve(output_path)?;
    let plaintext = Zeroizing::new(fs::read(input_path).map_err(|e| read_error(input_path, e))?);
    let passphrase = read_valid_passphrase(passphrase_reader)?;
    // A new file has nothing to check the passphrase against, so an
    // interactive entry is confirmed by typing it twice. See
    // `PassphraseReader::read_confirmation` for which sources confirm.
    if let Some(confirmation) = passphrase_reader.read_confirmation()? {
        if confirmation != passphrase {
            return Err(SaltyboxError::with_kind(
                ErrorCategory::User,
                ErrorKind::PassphraseConfirmationMismatch,
                "passphrase entries do not match; nothing was written",
            ));
        }
    }
    let armored = write_engine
        .encrypt(&passphrase, &plaintext)
        .map_err(|e| e.with_context("encryption failed"))?;
    write_file_secure(&output, armored.as_bytes(), None)
        .map_err(|e| e.with_context(format!("failed to write to {output_path:?}")))
}

/// Decrypt a file with a passphrase
///
/// Reads armored ciphertext from `input_path`, decrypts it using a passphrase from
/// `passphrase_reader`, and writes the plaintext to `output_path`.
///
/// Output is written atomically via a same-directory temporary file. A
/// symlinked `output_path` is followed and the file it ultimately points to
/// is replaced; the temporary file goes in that file's directory.
/// On Unix systems, the final file mode is set to 0o600 (read/write for owner only).
pub fn decrypt_file(
    input_path: &Path,
    output_path: &Path,
    passphrase_reader: &mut dyn PassphraseReader,
) -> Result<()> {
    check_output_path(output_path)?;
    let output = OutputDestination::resolve(output_path)?;
    let armored_bytes = fs::read(input_path).map_err(|e| read_error(input_path, e))?;
    let armored = String::from_utf8(armored_bytes)
        .map_err(|e| not_text_error("input file is not valid UTF-8", e))?;
    let passphrase = read_valid_passphrase(passphrase_reader)?;
    let (engine, ciphertext) =
        format::decode(&armored).map_err(|e| e.with_context("failed to unarmor"))?;
    let plaintext = engine
        .decrypt(&passphrase, &ciphertext)
        .map_err(|e| e.with_context("failed to decrypt"))?;
    write_file_secure(&output, &plaintext, None)
        .map_err(|e| e.with_context(format!("failed to write to {output_path:?}")))
}

/// Update an encrypted file with new plaintext using the same passphrase
///
/// This function:
/// 1. Decrypts the existing file at `crypt_path` to validate the passphrase
/// 2. Reads new plaintext from `plain_path`
/// 3. Encrypts the new plaintext with the validated passphrase
/// 4. Atomically writes to the same resolved directory and name. On Linux
///    and macOS, check the destination still names the file opened in step 1
///    immediately before rename. A concurrent replacement after that check
///    can still win the race against rename.
///
/// The atomic write ensures that either the old file or the new file exists,
/// never a partial/corrupted file.
///
/// The passphrase validation prevents accidental passphrase changes.
/// Set `passphrase_stdin` when the reader consumes process stdin. This rejects
/// a shared source before authentication and checks the opened handle before
/// reading the replacement. The reader itself does not need to expose its
/// source.
///
/// The output format follows `write_engine` alone, never the existing file's
/// format: updating with a different engine than the file was written with
/// silently converts it (this is the intended migration path).
pub fn update_file(
    plain_path: &Path,
    crypt_path: &Path,
    passphrase_reader: &mut dyn PassphraseReader,
    write_engine: &dyn format::FormatEngine,
    passphrase_stdin: bool,
) -> Result<()> {
    check_output_path(crypt_path)?;
    if passphrase_stdin {
        check_update_stdin_path(plain_path)?;
    }
    // Report identical arguments even if the file does not exist yet.
    if plain_path == crypt_path {
        return Err(update_input_conflict());
    }

    let output = OutputDestination::resolve(crypt_path)?;
    let mut existing = output
        .open_existing()
        .map_err(|e| read_error(crypt_path, e))?;
    if update_paths_conflict(plain_path, &output, &existing) {
        return Err(update_input_conflict());
    }
    let mut armored_bytes = Vec::new();
    existing
        .read_to_end(&mut armored_bytes)
        .map_err(|e| read_error(crypt_path, e))?;
    let armored = String::from_utf8(armored_bytes)
        .map_err(|e| not_text_error("encrypted file is not valid UTF-8", e))?;
    let passphrase = read_valid_passphrase(passphrase_reader)?;

    // Validate passphrase by decrypting existing file (discard plaintext)
    let (engine, ciphertext) =
        format::decode(&armored).map_err(|e| e.with_context("failed to unarmor"))?;
    engine
        .decrypt(&passphrase, &ciphertext)
        .map_err(|e| e.with_context("failed to decrypt"))?;

    let new_plaintext = read_update_plaintext(plain_path, &existing, passphrase_stdin)?;
    let new_armored = write_engine
        .encrypt(&passphrase, &new_plaintext)
        .map_err(|e| e.with_context("failed to encrypt"))?;
    write_file_secure(&output, new_armored.as_bytes(), Some(&existing))
        .map_err(|e| e.with_context(format!("failed to write to {crypt_path:?}")))
}

fn update_input_conflict() -> SaltyboxError {
    SaltyboxError::with_kind(
        ErrorCategory::User,
        ErrorKind::Io,
        "input and output paths must be different for update",
    )
}

/// Detects input aliases without resolving the original output path a second
/// time. On Unix the opened file carries the identity for both symbolic and
/// hard links. The other-platform branch can only compare resolved paths.
#[cfg(unix)]
fn update_paths_conflict(
    plain_path: &Path,
    _output: &OutputDestination,
    existing: &fs::File,
) -> bool {
    matches!(
        (fs::metadata(plain_path), existing.metadata()),
        (Ok(plain_meta), Ok(crypt_meta))
            if same_file(&plain_meta, &crypt_meta)
    )
}

#[cfg(not(unix))]
fn update_paths_conflict(
    plain_path: &Path,
    output: &OutputDestination,
    _existing: &fs::File,
) -> bool {
    matches!(
        (fs::canonicalize(plain_path), fs::canonicalize(&output.path)),
        (Ok(plain), Ok(encrypted)) if plain == encrypted
    )
}

/// Compares Unix file identity across aliases, including redirected descriptors.
#[cfg(unix)]
fn same_file(first: &fs::Metadata, second: &fs::Metadata) -> bool {
    use std::os::unix::fs::MetadataExt;

    first.dev() == second.dev() && first.ino() == second.ino()
}

/// Reads replacement data from the same handle whose identity was checked.
///
/// The pathname check avoids opening a known stdin alias that could block.
/// The handle checks catch changes since the earlier pathname checks and
/// keep the encrypted file and passphrase source out of the replacement.
fn read_update_plaintext(
    path: &Path,
    _existing: &fs::File,
    passphrase_stdin: bool,
) -> Result<Zeroizing<Vec<u8>>> {
    if passphrase_stdin {
        check_update_stdin_path(path)?;
    }
    let mut input = fs::File::open(path).map_err(|err| read_error(path, err))?;
    #[cfg(unix)]
    {
        let metadata = input.metadata().map_err(|err| read_error(path, err))?;
        let existing = _existing.metadata().map_err(|err| {
            SaltyboxError::with_kind_and_source(
                ErrorCategory::User,
                ErrorKind::Io,
                "failed to inspect existing encrypted file for update",
                err,
            )
        })?;
        if same_file(&metadata, &existing) {
            return Err(update_input_conflict());
        }
        if passphrase_stdin {
            reject_stdin_alias(&metadata)?;
        }
    }
    let mut plaintext = Zeroizing::new(Vec::new());
    input
        .read_to_end(&mut plaintext)
        .map_err(|err| read_error(path, err))?;
    Ok(plaintext)
}

/// Rejects a known stdin alias before opening a pathname that may block.
/// Leave missing or inaccessible paths for the ordinary input read to diagnose.
#[cfg(unix)]
fn check_update_stdin_path(path: &Path) -> Result<()> {
    let Ok(input) = fs::metadata(path) else {
        return Ok(());
    };
    reject_stdin_alias(&input)
}

/// Checks stdin without consuming bytes or taking ownership of fd 0.
#[cfg(unix)]
fn reject_stdin_alias(input: &fs::Metadata) -> Result<()> {
    use std::os::fd::AsFd;

    let stdin = io::stdin()
        .as_fd()
        .try_clone_to_owned()
        .and_then(|fd| fs::File::from(fd).metadata())
        .map_err(|err| {
            SaltyboxError::with_kind_and_source(
                ErrorCategory::User,
                ErrorKind::Io,
                "failed to inspect standard input for update",
                err,
            )
        })?;
    let aliases_stdin = same_file(input, &stdin);
    // Darwin's descriptor paths can report a narrower inode number for pipes
    // than fstat does. Compare the pathname view as well as the open file.
    #[cfg(target_os = "macos")]
    let aliases_stdin =
        aliases_stdin || fs::metadata("/dev/fd/0").is_ok_and(|alias| same_file(input, &alias));
    if aliases_stdin {
        return Err(SaltyboxError::with_kind(
            ErrorCategory::User,
            ErrorKind::Io,
            "update requires separate sources for the passphrase and replacement input",
        ));
    }
    Ok(())
}

/// Other platforms accept the input without the Unix descriptor check.
#[cfg(not(unix))]
fn check_update_stdin_path(_path: &Path) -> Result<()> {
    Ok(())
}

/// Rejects output paths that cannot name a file, before any I/O touches them.
///
/// Empty paths and trailing separators often come from unset shell variables.
/// A final `.` or `..` names a directory. Check the raw argument because `Path`
/// can normalize a trailing `.` away. All three commands run this before
/// reading input or prompting. A bad `-o` should fail before the user types a
/// passphrase and waits for key derivation.
fn check_output_path(path: &Path) -> Result<()> {
    // An empty path is almost always an unset shell variable. Name the
    // mistake here so output resolution can assume the user supplied a filename.
    if path.as_os_str().is_empty() {
        return Err(SaltyboxError::with_kind(
            ErrorCategory::User,
            ErrorKind::Io,
            "empty output path is not allowed (note that an unset shell variable expands to empty)",
        ));
    }
    // A trailing separator requires a directory. Inspect the original path
    // because `Path` normalizes `nodir/` to `nodir`. This is usually an unset
    // shell variable (`-o "$DIR/$NAME"`).
    // Checking the last encoded byte is sound because every separator is ASCII,
    // and bytes of multi-byte characters in UTF-8 and WTF-8 are always >= 0x80.
    let encoded = path.as_os_str().as_encoded_bytes();
    let is_separator = |&byte: &u8| std::path::is_separator(char::from(byte));
    if encoded.last().is_some_and(is_separator) {
        return Err(SaltyboxError::with_kind(
            ErrorCategory::User,
            ErrorKind::Io,
            format!(
                "output path {path:?} ends in a path separator, so it names a directory rather than a file (an unset shell variable at the end of the path, as in \"$DIR/$NAME\", produces this)"
            ),
        ));
    }
    // The final name must be checked before Path's component normalization
    // can turn `dir/.` into `dir` and put the tempfile in dir's parent.
    if matches!(encoded.rsplit(is_separator).next(), Some(b"." | b"..")) {
        return Err(SaltyboxError::with_kind(
            ErrorCategory::User,
            ErrorKind::Io,
            format!("output path {path:?} ends in '.' or '..', so it names a directory"),
        ));
    }
    Ok(())
}

/// Publishes complete owner-only output through the destination chosen before
/// reading the passphrase. Cleanup and rename use that same destination.
///
/// A failed write or validation leaves any existing output alone. A directory
/// sync failure can occur after the rename, when the output is already in place.
fn write_file_secure(
    destination: &OutputDestination,
    contents: &[u8],
    existing: Option<&fs::File>,
) -> Result<()> {
    let path = &destination.path;
    // A name checked before the prompt may have changed since then.
    destination.verify_for_save(existing)?;
    let mut temp_file = destination.create_tempfile().map_err(|e| {
        SaltyboxError::with_kind_and_source(
            ErrorCategory::User,
            ErrorKind::Io,
            format!("failed to create tempfile for {path:?}"),
            e,
        )
    })?;

    if let Err(err) = fill_tempfile(&mut temp_file, path, contents) {
        return Err(discard_tempfile(destination, temp_file, err));
    }
    publish_tempfile(destination, temp_file, existing)?;
    destination.sync_directory().map_err(|e| {
        SaltyboxError::with_kind_and_source(
            ErrorCategory::Internal,
            ErrorKind::Io,
            format!("failed to sync directory after writing {path:?}"),
            e,
        )
    })
}

/// Rechecks the destination after writing and syncing the tempfile. A
/// failed check uses the same cleanup path as a failed rename.
fn publish_tempfile(
    destination: &OutputDestination,
    temp_file: NamedTempFile,
    existing: Option<&fs::File>,
) -> Result<()> {
    if let Err(err) = destination.verify_for_save(existing) {
        return Err(discard_tempfile(destination, temp_file, err));
    }
    rename_tempfile(destination, temp_file)
}

/// Reports rename errors at the destination and cleans up the staged file.
fn rename_tempfile(destination: &OutputDestination, temp_file: NamedTempFile) -> Result<()> {
    if let Err(tempfile::PersistError { error, file }) = destination.persist_tempfile(temp_file) {
        let err = SaltyboxError::with_kind_and_source(
            ErrorCategory::User,
            ErrorKind::Io,
            format!("failed to rename to target file {:?}", destination.path),
            error,
        );
        return Err(discard_tempfile(destination, file, err));
    }
    Ok(())
}

/// Retains path-based publication for builds outside the supported platforms.
/// Other Unix builds still hold a readable directory open for the final sync.
#[cfg(not(any(target_os = "linux", target_os = "macos")))]
struct OutputDestination {
    path: PathBuf,
    #[cfg(unix)]
    directory: fs::File,
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
impl OutputDestination {
    fn resolve(path: &Path) -> Result<Self> {
        let path = resolve_output_symlink(path)?.unwrap_or_else(|| path.to_path_buf());
        #[cfg(unix)]
        let directory = fs::File::open(Self::parent(&path))
            .map_err(|err| directory_error(Self::parent(&path), &path, err))?;
        Ok(Self {
            path,
            #[cfg(unix)]
            directory,
        })
    }

    fn open_existing(&self) -> io::Result<fs::File> {
        fs::File::open(&self.path)
    }

    fn create_tempfile(&self) -> io::Result<NamedTempFile> {
        tempfile_builder().tempfile_in(Self::parent(&self.path))
    }

    fn parent(path: &Path) -> &Path {
        path.parent()
            .filter(|entry| !entry.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."))
    }

    fn persist_tempfile(
        &self,
        file: NamedTempFile,
    ) -> std::result::Result<(), tempfile::PersistError> {
        file.persist(&self.path).map(drop)
    }

    fn sync_directory(&self) -> io::Result<()> {
        #[cfg(unix)]
        self.directory.sync_all()?;
        Ok(())
    }

    fn remove_tempfile(&self, path: &Path) -> io::Result<()> {
        fs::remove_file(path)
    }

    fn tempfile_location(&self, path: &Path) -> String {
        format!("{path:?}")
    }

    fn verify_for_save(&self, _existing: Option<&fs::File>) -> Result<()> {
        Ok(())
    }
}

/// A missing directory gets a specific diagnostic before any output is written.
#[cfg(unix)]
fn directory_error(directory: &Path, path: &Path, err: io::Error) -> SaltyboxError {
    let message = if err.kind() == io::ErrorKind::NotFound {
        format!("output directory {directory:?} does not exist")
    } else {
        format!("failed to open output directory {directory:?} while preparing to write {path:?}")
    };
    SaltyboxError::with_kind_and_source(ErrorCategory::User, ErrorKind::Io, message, err)
}

/// Resolves an output path that is a symbolic link to the file it ultimately
/// points to, following chains of links. Returns `None` when the path is not
/// a symlink, when nothing exists there yet, or when it cannot be inspected
/// at all, so the caller writes to the path as given; in the last case the
/// caller's directory open reports the failure with its own message.
///
/// Writing through the link keeps reads and writes consistent. The final
/// step of a write renames a tempfile onto the output path, and a rename
/// replaces the directory entry it lands on: aimed at the link, it would turn
/// the link into a regular file and leave the real file stale. For `update`,
/// which has just validated the passphrase by reading the existing file
/// through the link, that meant reporting success while the file it checked
/// was never updated.
///
/// A link whose target does not exist is refused rather than followed to
/// create the target, as SPEC.md requires. Hard links need no handling here;
/// renaming onto one name simply leaves the file's other names with the old
/// contents.
#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn resolve_output_symlink(path: &Path) -> Result<Option<PathBuf>> {
    match fs::symlink_metadata(path) {
        Ok(meta) if meta.file_type().is_symlink() => match fs::canonicalize(path) {
            Ok(target) => Ok(Some(target)),
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                // Naming where the link points is what the user needs to fix
                // it; for a chain this is the first hop.
                let msg = match fs::read_link(path) {
                    Ok(target) => format!(
                        "output path {path:?} is a symlink to {target:?}, which does not exist"
                    ),
                    Err(_) => format!("output path {path:?} is a symlink to a nonexistent file"),
                };
                Err(SaltyboxError::with_kind(
                    ErrorCategory::User,
                    ErrorKind::Io,
                    msg,
                ))
            }
            Err(e) => Err(SaltyboxError::with_kind_and_source(
                ErrorCategory::User,
                ErrorKind::Io,
                format!("failed to resolve output symlink {path:?}"),
                e,
            )),
        },
        _ => Ok(None),
    }
}

/// Supplies the `.saltybox-*.tmp` name so users can recognize a leftover file.
/// `OutputDestination::create_tempfile` creates it in the destination
/// directory so a rename can publish it atomically on the same filesystem.
fn tempfile_builder() -> tempfile::Builder<'static, 'static> {
    let mut builder = tempfile::Builder::new();
    builder.prefix(TEMPFILE_PREFIX).suffix(TEMPFILE_SUFFIX);
    builder
}

/// Writes, flushes, syncs, and (on Unix) restricts the tempfile, so a rename
/// that follows always publishes complete, durable, owner-only contents.
fn fill_tempfile(temp_file: &mut NamedTempFile, path: &Path, contents: &[u8]) -> Result<()> {
    temp_file.write_all(contents).map_err(|e| {
        SaltyboxError::with_kind_and_source(
            ErrorCategory::Internal,
            ErrorKind::Io,
            format!("failed to write {path:?}"),
            e,
        )
    })?;
    // Ensure persisted rename always points to fully written data.
    temp_file.flush().map_err(|e| {
        SaltyboxError::with_kind_and_source(
            ErrorCategory::Internal,
            ErrorKind::Io,
            format!("failed to flush {path:?}"),
            e,
        )
    })?;
    temp_file.as_file().sync_all().map_err(|e| {
        SaltyboxError::with_kind_and_source(
            ErrorCategory::Internal,
            ErrorKind::Io,
            format!("failed to sync {path:?}"),
            e,
        )
    })?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        temp_file
            .as_file()
            .set_permissions(fs::Permissions::from_mode(0o600))
            .map_err(|e| {
                SaltyboxError::with_kind_and_source(
                    ErrorCategory::Internal,
                    ErrorKind::Io,
                    "failed to set tempfile permissions",
                    e,
                )
            })?;
    }
    Ok(())
}

/// Removes the tempfile after a failure that happened once it existed, and
/// returns the failure's error, extended when the removal itself fails.
///
/// Every failure between creating the tempfile and a successful rename goes
/// through here. The removal is explicit instead of being left to
/// `NamedTempFile`'s destructor for two reasons. The destructor ignores a
/// failed removal, and for `decrypt` a leftover tempfile is a copy of the
/// plaintext, so the user has to be told where it is. And the destructor ties
/// removal to whoever ends up holding the handle, and does not run at all if
/// the process exits without unwinding.
///
/// Use the destination's directory to remove the same temporary name even
/// if the original path moved. A file that is already gone counts as removed.
fn discard_tempfile(
    destination: &OutputDestination,
    temp_file: NamedTempFile,
    err: SaltyboxError,
) -> SaltyboxError {
    let (file, mut temp_path) = temp_file.into_parts();
    drop(file);
    let removal = destination.remove_tempfile(&temp_path);
    // Disarm the `TempPath` destructor: removal was just attempted, and a
    // silent second attempt could only hide what the message below reports.
    temp_path.disable_cleanup(true);
    let tempfile_path = temp_path.to_path_buf();
    match removal {
        Ok(()) => err,
        Err(cleanup_err) if cleanup_err.kind() == io::ErrorKind::NotFound => err,
        Err(cleanup_err) => {
            let location = destination.tempfile_location(&tempfile_path);
            err.with_context(format!(
                "failed to remove tempfile {location} after the error below ({cleanup_err}). Remove it by hand"
            ))
        }
    }
}

/// Wraps the rejection of an encrypted file that is not valid UTF-8.
///
/// The read itself succeeded; what failed is the armor's requirement that the
/// file be text, so this is an armoring error (`ArmoringInvalid`), not an I/O
/// one, and a user error like every other malformed input.
fn not_text_error(msg: &'static str, err: std::string::FromUtf8Error) -> SaltyboxError {
    SaltyboxError::with_kind_and_source(ErrorCategory::User, ErrorKind::ArmoringInvalid, msg, err)
}

/// Wraps a failed read of a user-supplied path as a user error.
///
/// Every I/O failure on a path the user named is classified as a user error,
/// not just a missing file: a directory passed as a file, a permission
/// denial, an unreadable mount are all the caller's environment. Internal is
/// reserved for failures on the tool's own tempfile writes and syncs, where
/// the path was chosen by this code. SPEC.md states the split.
fn read_error(path: &Path, err: io::Error) -> SaltyboxError {
    SaltyboxError::with_kind_and_source(
        ErrorCategory::User,
        ErrorKind::Io,
        format!("failed to read from {path:?}"),
        err,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::{ErrorCategory, ErrorKind};
    use crate::format_v2::V2Engine;
    use crate::passphrase::{ConfirmingPassphraseReader, ConstantPassphraseReader};
    use std::fs;
    use tempfile::TempDir;

    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;

    /// Most tests here exercise file-handling behavior that does not depend
    /// on which format is written; these wrappers keep those call sites
    /// one-liners. Tests where the engine choice is the point pass engines
    /// to [`encrypt_file`]/[`update_file`] explicitly.
    fn encrypt_with_default_engine(
        input_path: &Path,
        output_path: &Path,
        passphrase_reader: &mut dyn PassphraseReader,
    ) -> Result<()> {
        encrypt_file(
            input_path,
            output_path,
            passphrase_reader,
            format::default_write_engine(),
        )
    }

    /// See [`encrypt_with_default_engine`].
    fn update_with_default_engine(
        plain_path: &Path,
        crypt_path: &Path,
        passphrase_reader: &mut dyn PassphraseReader,
    ) -> Result<()> {
        update_file(
            plain_path,
            crypt_path,
            passphrase_reader,
            format::default_write_engine(),
            false,
        )
    }

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let temp_dir = TempDir::new().unwrap();
        let plain_path = temp_dir.path().join("plain.txt");
        let crypt_path = temp_dir.path().join("crypt.txt.saltybox");
        let decrypted_path = temp_dir.path().join("decrypted.txt");

        let plaintext = b"Hello, saltybox!";
        fs::write(&plain_path, plaintext).unwrap();

        let mut reader = ConstantPassphraseReader::new(b"test password".to_vec());
        encrypt_with_default_engine(&plain_path, &crypt_path, &mut reader).unwrap();
        assert!(crypt_path.exists());

        let mut reader = ConstantPassphraseReader::new(b"test password".to_vec());
        decrypt_file(&crypt_path, &decrypted_path, &mut reader).unwrap();
        let decrypted = fs::read(&decrypted_path).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_encrypt_file_with_v2_engine_roundtrips() {
        let temp_dir = TempDir::new().unwrap();
        let plain_path = temp_dir.path().join("plain.txt");
        let crypt_path = temp_dir.path().join("crypt.txt.saltybox");
        let decrypted_path = temp_dir.path().join("decrypted.txt");

        fs::write(&plain_path, b"v2 write path").unwrap();

        let mut reader = ConstantPassphraseReader::new(b"pw".to_vec());
        encrypt_file(&plain_path, &crypt_path, &mut reader, &V2Engine).unwrap();
        assert!(
            fs::read_to_string(&crypt_path)
                .unwrap()
                .starts_with("saltybox2:")
        );

        let mut reader = ConstantPassphraseReader::new(b"pw".to_vec());
        decrypt_file(&crypt_path, &decrypted_path, &mut reader).unwrap();
        assert_eq!(fs::read(&decrypted_path).unwrap(), b"v2 write path");
    }

    /// The output format follows the write engine alone, never the input
    /// file's format: updating a saltybox1 file with the (v2) default engine
    /// upgrades it. This is the intended migration path for old files. The
    /// v1 file is constructed from the frozen v1 modules directly, since
    /// nothing exposes a v1 write engine anymore.
    #[test]
    fn test_update_upgrades_v1_file_to_default_format() {
        let temp_dir = TempDir::new().unwrap();
        let plain_path = temp_dir.path().join("plain.txt");
        let crypt_path = temp_dir.path().join("crypt.txt.saltybox");
        let decrypted_path = temp_dir.path().join("decrypted.txt");

        let v1_armored =
            crate::varmor::wrap(&crate::secretcrypt_v1::encrypt(b"pw", b"original").unwrap());
        fs::write(&crypt_path, &v1_armored).unwrap();

        fs::write(&plain_path, b"upgraded").unwrap();
        let mut reader = ConstantPassphraseReader::new(b"pw".to_vec());
        update_with_default_engine(&plain_path, &crypt_path, &mut reader).unwrap();
        assert!(
            fs::read_to_string(&crypt_path)
                .unwrap()
                .starts_with("saltybox2:")
        );

        let mut reader = ConstantPassphraseReader::new(b"pw".to_vec());
        decrypt_file(&crypt_path, &decrypted_path, &mut reader).unwrap();
        assert_eq!(fs::read(&decrypted_path).unwrap(), b"upgraded");
    }

    #[test]
    fn test_update_file() {
        let temp_dir = TempDir::new().unwrap();
        let plain1_path = temp_dir.path().join("plain1.txt");
        let plain2_path = temp_dir.path().join("plain2.txt");
        let crypt_path = temp_dir.path().join("crypt.txt.saltybox");

        let plaintext1 = b"Initial content";
        fs::write(&plain1_path, plaintext1).unwrap();

        let mut reader = ConstantPassphraseReader::new(b"test password".to_vec());
        encrypt_with_default_engine(&plain1_path, &crypt_path, &mut reader).unwrap();

        let plaintext2 = b"Updated content";
        fs::write(&plain2_path, plaintext2).unwrap();

        let mut reader = ConstantPassphraseReader::new(b"test password".to_vec());
        update_with_default_engine(&plain2_path, &crypt_path, &mut reader).unwrap();

        let decrypted_path = temp_dir.path().join("decrypted.txt");
        let mut reader = ConstantPassphraseReader::new(b"test password".to_vec());
        decrypt_file(&crypt_path, &decrypted_path, &mut reader).unwrap();

        let decrypted = fs::read(&decrypted_path).unwrap();
        assert_eq!(decrypted, plaintext2);
    }

    #[test]
    fn test_update_rejects_identical_input_output_path() {
        let temp_dir = TempDir::new().unwrap();
        let plain_path = temp_dir.path().join("plain.txt");
        let crypt_path = temp_dir.path().join("crypt.txt.saltybox");

        let original = b"Initial content";
        fs::write(&plain_path, original).unwrap();

        let mut reader = ConstantPassphraseReader::new(b"test password".to_vec());
        encrypt_with_default_engine(&plain_path, &crypt_path, &mut reader).unwrap();

        let mut reader = ConstantPassphraseReader::new(b"test password".to_vec());
        let result = update_with_default_engine(&crypt_path, &crypt_path, &mut reader);

        let err = result.expect_err("expected path conflict failure");
        assert_eq!(err.category, ErrorCategory::User);
        assert_eq!(err.kind, Some(ErrorKind::Io));
        assert_eq!(
            err.message(),
            "input and output paths must be different for update"
        );

        let decrypted_path = temp_dir.path().join("decrypted.txt");
        let mut reader = ConstantPassphraseReader::new(b"test password".to_vec());
        decrypt_file(&crypt_path, &decrypted_path, &mut reader).unwrap();
        let decrypted = fs::read(&decrypted_path).unwrap();
        assert_eq!(decrypted, original);
    }

    #[test]
    fn test_update_rejects_canonical_alias_of_output_path() {
        let temp_dir = TempDir::new().unwrap();
        let plain_path = temp_dir.path().join("plain.txt");
        let crypt_path = temp_dir.path().join("crypt.txt.saltybox");
        let alias_dir = temp_dir.path().join("alias");
        let alias_path = alias_dir.join("..").join("crypt.txt.saltybox");

        let original = b"Initial content";
        fs::write(&plain_path, original).unwrap();

        let mut reader = ConstantPassphraseReader::new(b"test password".to_vec());
        encrypt_with_default_engine(&plain_path, &crypt_path, &mut reader).unwrap();

        fs::create_dir(&alias_dir).unwrap();

        let mut reader = ConstantPassphraseReader::new(b"test password".to_vec());
        let result = update_with_default_engine(&alias_path, &crypt_path, &mut reader);

        let err = result.expect_err("expected canonical path conflict failure");
        assert_eq!(err.category, ErrorCategory::User);
        assert_eq!(err.kind, Some(ErrorKind::Io));
        assert_eq!(
            err.message(),
            "input and output paths must be different for update"
        );

        let decrypted_path = temp_dir.path().join("decrypted.txt");
        let mut reader = ConstantPassphraseReader::new(b"test password".to_vec());
        decrypt_file(&crypt_path, &decrypted_path, &mut reader).unwrap();
        let decrypted = fs::read(&decrypted_path).unwrap();
        assert_eq!(decrypted, original);
    }

    /// A symlink to the ciphertext, passed as the new-plaintext input, must be
    /// rejected and the ciphertext left intact.
    ///
    /// Symlinks are the alias class SPEC.md names explicitly, yet the
    /// `..`-traversal test is the only one exercising the canonicalization
    /// path. On Unix, following the input link for metadata must identify the
    /// same inode held open as the output. Without that check, update could
    /// read the old ciphertext as the replacement plaintext and clobber it.
    #[test]
    #[cfg(unix)]
    fn test_update_rejects_symlink_alias_of_output_path() {
        let temp_dir = TempDir::new().unwrap();
        let plain_path = temp_dir.path().join("plain.txt");
        let crypt_path = temp_dir.path().join("crypt.txt.saltybox");
        let symlink_path = temp_dir.path().join("crypt-symlink.saltybox");

        let original = b"Initial content";
        fs::write(&plain_path, original).unwrap();

        let mut reader = ConstantPassphraseReader::new(b"test password".to_vec());
        encrypt_with_default_engine(&plain_path, &crypt_path, &mut reader).unwrap();

        std::os::unix::fs::symlink(&crypt_path, &symlink_path).unwrap();

        let mut reader = ConstantPassphraseReader::new(b"test password".to_vec());
        let result = update_with_default_engine(&symlink_path, &crypt_path, &mut reader);

        let err = result.expect_err("expected symlink path conflict failure");
        assert_eq!(err.category, ErrorCategory::User);
        assert_eq!(err.kind, Some(ErrorKind::Io));
        assert_eq!(
            err.message(),
            "input and output paths must be different for update"
        );

        let decrypted_path = temp_dir.path().join("decrypted.txt");
        let mut reader = ConstantPassphraseReader::new(b"test password".to_vec());
        decrypt_file(&crypt_path, &decrypted_path, &mut reader).unwrap();
        let decrypted = fs::read(&decrypted_path).unwrap();
        assert_eq!(decrypted, original);
    }

    /// `update` through a symlinked output path replaces the file the link
    /// points to and leaves the link in place.
    ///
    /// The passphrase check reads the existing file through the link, so the
    /// write has to land on the same file: renaming onto the link itself used
    /// to replace the link with a regular file and leave the real file (the
    /// one that was validated) holding the old ciphertext, while reporting
    /// success. SPEC.md now requires reads and writes to agree.
    #[test]
    #[cfg(unix)]
    fn test_update_through_symlink_replaces_target_and_keeps_link() {
        let temp_dir = TempDir::new().unwrap();
        let vault_dir = temp_dir.path().join("vault");
        fs::create_dir(&vault_dir).unwrap();
        let real_path = vault_dir.join("secret.salty");
        let link_path = temp_dir.path().join("link.salty");
        let plain_path = temp_dir.path().join("plain.txt");

        fs::write(&plain_path, b"old").unwrap();
        let mut reader = ConstantPassphraseReader::new(b"pw".to_vec());
        encrypt_with_default_engine(&plain_path, &real_path, &mut reader).unwrap();
        std::os::unix::fs::symlink(&real_path, &link_path).unwrap();

        fs::write(&plain_path, b"new").unwrap();
        let mut reader = ConstantPassphraseReader::new(b"pw".to_vec());
        update_with_default_engine(&plain_path, &link_path, &mut reader).unwrap();

        assert!(
            fs::symlink_metadata(&link_path)
                .unwrap()
                .file_type()
                .is_symlink(),
            "the link must survive the update"
        );
        let decrypted_path = temp_dir.path().join("decrypted.txt");
        let mut reader = ConstantPassphraseReader::new(b"pw".to_vec());
        decrypt_file(&real_path, &decrypted_path, &mut reader).unwrap();
        assert_eq!(fs::read(&decrypted_path).unwrap(), b"new");
        // Nothing was left behind in the target's directory.
        let mut vault_entries: Vec<_> = fs::read_dir(&vault_dir)
            .unwrap()
            .map(|entry| entry.unwrap().file_name().into_string().unwrap())
            .collect();
        vault_entries.sort();
        assert_eq!(vault_entries, ["secret.salty"]);
    }

    /// Makes the filesystem change between opening the encrypted file and saving it.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    struct RenameWhilePrompting<'a> {
        from: &'a Path,
        to: &'a Path,
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    impl PassphraseReader for RenameWhilePrompting<'_> {
        fn read_passphrase(&mut self) -> Result<Zeroizing<Vec<u8>>> {
            fs::rename(self.from, self.to).unwrap();
            Ok(Zeroizing::new(b"pw".to_vec()))
        }
    }

    /// Replacing a parent link during an update cannot redirect publication.
    /// The original destination is updated and the unrelated directory stays untouched.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn test_update_keeps_resolved_directory_when_parent_link_changes() {
        let temp = TempDir::new().unwrap();
        let first = temp.path().join("first");
        let second = temp.path().join("second");
        let route = temp.path().join("route");
        let changed_route = temp.path().join("changed-route");
        let plaintext = temp.path().join("plaintext");
        let original = first.join("secret.salty");
        let untouched = second.join("secret.salty");
        fs::create_dir(&first).unwrap();
        fs::create_dir(&second).unwrap();
        fs::write(&plaintext, b"original").unwrap();
        let mut reader = ConstantPassphraseReader::new(b"pw".to_vec());
        encrypt_with_default_engine(&plaintext, &original, &mut reader).unwrap();
        fs::write(&untouched, b"other file").unwrap();
        std::os::unix::fs::symlink("first", &route).unwrap();
        std::os::unix::fs::symlink("second", &changed_route).unwrap();

        fs::write(&plaintext, b"replacement").unwrap();
        let mut reader = RenameWhilePrompting {
            from: &changed_route,
            to: &route,
        };
        update_with_default_engine(&plaintext, &route.join("secret.salty"), &mut reader).unwrap();

        let decoded = temp.path().join("decoded");
        let mut reader = ConstantPassphraseReader::new(b"pw".to_vec());
        decrypt_file(&original, &decoded, &mut reader).unwrap();
        assert_eq!(fs::read(decoded).unwrap(), b"replacement");
        assert_eq!(fs::read(untouched).unwrap(), b"other file");
    }

    /// A different file at the final name during the prompt must stop the
    /// save before publication and leave that entry alone.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn test_update_rejects_a_replaced_final_entry() {
        let temp = TempDir::new().unwrap();
        let encrypted = temp.path().join("existing.salty");
        let plaintext = temp.path().join("plaintext");
        let incoming = temp.path().join("incoming");
        fs::write(&plaintext, b"original").unwrap();
        let mut reader = ConstantPassphraseReader::new(b"pw".to_vec());
        encrypt_with_default_engine(&plaintext, &encrypted, &mut reader).unwrap();
        fs::write(&incoming, b"keep me").unwrap();

        let mut reader = RenameWhilePrompting {
            from: &incoming,
            to: &encrypted,
        };
        let err = update_with_default_engine(&plaintext, &encrypted, &mut reader).unwrap_err();
        let cause = std::error::Error::source(&err).unwrap();
        assert!(
            cause
                .to_string()
                .contains("changed while preparing the update"),
            "{err}"
        );
        assert_eq!(fs::read(encrypted).unwrap(), b"keep me");
        assert_eq!(fs::read_dir(temp.path()).unwrap().count(), 2);
    }

    /// The replacement pathname can change during the prompt. Update must
    /// check the file it actually opens before consuming replacement bytes.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn test_update_rejects_an_input_alias_created_during_the_prompt() {
        let temp = TempDir::new().unwrap();
        let plain = temp.path().join("plain");
        let encrypted = temp.path().join("encrypted");
        let alias = temp.path().join("alias");
        fs::write(&plain, b"original").unwrap();
        let mut reader = ConstantPassphraseReader::new(b"pw".to_vec());
        encrypt_with_default_engine(&plain, &encrypted, &mut reader).unwrap();
        let original = fs::read(&encrypted).unwrap();
        fs::hard_link(&encrypted, &alias).unwrap();

        let mut reader = RenameWhilePrompting {
            from: &alias,
            to: &plain,
        };
        let err = update_with_default_engine(&plain, &encrypted, &mut reader).unwrap_err();
        assert_eq!(err.category, ErrorCategory::User);
        assert_eq!(err.message(), update_input_conflict().message());
        assert_eq!(fs::read(&encrypted).unwrap(), original);
    }

    /// A final output link requires an existing target, including after the
    /// user moves that target away while decrypt waits for a passphrase.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn test_decrypt_does_not_recreate_a_target_moved_during_the_prompt() {
        let temp = TempDir::new().unwrap();
        let plain = temp.path().join("plain");
        let encrypted = temp.path().join("encrypted");
        let target = temp.path().join("target");
        let moved = temp.path().join("moved");
        let link = temp.path().join("link");
        fs::write(&plain, b"secret").unwrap();
        let mut reader = ConstantPassphraseReader::new(b"pw".to_vec());
        encrypt_with_default_engine(&plain, &encrypted, &mut reader).unwrap();
        fs::write(&target, b"keep me").unwrap();
        std::os::unix::fs::symlink("target", &link).unwrap();

        let mut reader = RenameWhilePrompting {
            from: &target,
            to: &moved,
        };
        let err = decrypt_file(&encrypted, &link, &mut reader).unwrap_err();
        let cause = std::error::Error::source(&err).unwrap();
        assert_eq!(err.category, ErrorCategory::User);
        assert!(cause.to_string().contains("no longer exists"), "{err}");
        assert_eq!(fs::read_link(&link).unwrap(), Path::new("target"));
        assert!(!target.exists());
        assert_eq!(fs::read(&moved).unwrap(), b"keep me");
        assert_eq!(fs::read_dir(temp.path()).unwrap().count(), 4);
    }

    /// A pipe destination could block update or be overwritten by another
    /// command. Reject it during destination preparation, even behind a link.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn test_output_pipe_is_refused_without_replacement() {
        use std::os::unix::fs::FileTypeExt;

        let temp = TempDir::new().unwrap();
        let pipe = temp.path().join("pipe");
        let link = temp.path().join("link");
        let missing_input = temp.path().join("missing");
        let resolved = OutputDestination::resolve(&pipe).unwrap();
        assert!(
            std::process::Command::new("mkfifo")
                .arg(&pipe)
                .status()
                .unwrap()
                .success()
        );
        std::os::unix::fs::symlink("pipe", &link).unwrap();

        let mut reader = ConstantPassphraseReader::new(b"pw".to_vec());
        for destination in [&pipe, &link] {
            for result in [
                encrypt_with_default_engine(&missing_input, destination, &mut reader),
                decrypt_file(&missing_input, destination, &mut reader),
                update_with_default_engine(&missing_input, destination, &mut reader),
            ] {
                let err = result.unwrap_err();
                assert!(err.to_string().contains("is not a regular file"), "{err}");
            }
        }

        // The name was absent at resolution. Make tempfile creation fail if
        // attempted, so the special-file diagnostic pins the order at save.
        let original_permissions = fs::metadata(temp.path()).unwrap().permissions();
        fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o500)).unwrap();
        let result = write_file_secure(&resolved, b"output", None);
        fs::set_permissions(temp.path(), original_permissions).unwrap();
        let err = result.unwrap_err();
        assert!(err.to_string().contains("is not a regular file"), "{err}");

        assert!(fs::symlink_metadata(pipe).unwrap().file_type().is_fifo());
        assert!(fs::symlink_metadata(link).unwrap().file_type().is_symlink());
        assert_eq!(fs::read_dir(temp.path()).unwrap().count(), 2);
    }

    /// A chain of symlinks is followed to the final file, which the output
    /// replaces, and every link in the chain survives. This is the
    /// "ultimate target" half of the SPEC.md rule: resolving only one level
    /// would still overwrite a link.
    #[test]
    #[cfg(unix)]
    fn test_encrypt_through_symlink_chain_replaces_final_target() {
        let temp_dir = TempDir::new().unwrap();
        let plain_path = temp_dir.path().join("plain.txt");
        let target_path = temp_dir.path().join("target.salty");
        let inner_link = temp_dir.path().join("inner.salty");
        let outer_link = temp_dir.path().join("outer.salty");

        fs::write(&plain_path, b"payload").unwrap();
        fs::write(&target_path, b"placeholder").unwrap();
        std::os::unix::fs::symlink(&target_path, &inner_link).unwrap();
        std::os::unix::fs::symlink(&inner_link, &outer_link).unwrap();

        let mut reader = ConstantPassphraseReader::new(b"pw".to_vec());
        encrypt_with_default_engine(&plain_path, &outer_link, &mut reader).unwrap();

        for link in [&inner_link, &outer_link] {
            assert!(
                fs::symlink_metadata(link).unwrap().file_type().is_symlink(),
                "{} must still be a symlink",
                link.display()
            );
        }
        let decrypted_path = temp_dir.path().join("decrypted.txt");
        let mut reader = ConstantPassphraseReader::new(b"pw".to_vec());
        decrypt_file(&target_path, &decrypted_path, &mut reader).unwrap();
        assert_eq!(fs::read(&decrypted_path).unwrap(), b"payload");
    }

    /// An output symlink whose target does not exist is refused as a user
    /// error naming where the link points without printing its control characters.
    /// Neither the target nor
    /// anything else is created. SPEC.md requires refusing rather than
    /// following the link to create its target.
    #[test]
    #[cfg(unix)]
    fn test_output_symlink_to_nonexistent_file_is_rejected() {
        let temp_dir = TempDir::new().unwrap();
        let plain_path = temp_dir.path().join("plain.txt");
        let missing_target = temp_dir.path().join("missing\u{1b}.salty");
        let link_path = temp_dir.path().join("dangling.salty");

        fs::write(&plain_path, b"payload").unwrap();
        std::os::unix::fs::symlink(&missing_target, &link_path).unwrap();

        let mut reader = ConstantPassphraseReader::new(b"pw".to_vec());
        let err = encrypt_with_default_engine(&plain_path, &link_path, &mut reader)
            .expect_err("expected dangling output symlink to be refused");

        assert_eq!(err.category, ErrorCategory::User);
        assert_eq!(err.kind, Some(ErrorKind::Io));
        let mut chain = String::new();
        let mut source: Option<&(dyn std::error::Error + 'static)> = Some(&err);
        while let Some(e) = source {
            chain.push_str(&e.to_string());
            chain.push('\n');
            source = e.source();
        }
        assert!(
            chain.contains(&format!(
                "is a symlink to {missing_target:?}, which does not exist"
            )),
            "chain: {chain}"
        );
        assert!(
            !chain.contains('\u{1b}'),
            "diagnostic contains a literal ESC"
        );
        let mut entries: Vec<_> = fs::read_dir(temp_dir.path())
            .unwrap()
            .map(|entry| entry.unwrap().file_name().into_string().unwrap())
            .collect();
        entries.sort();
        assert_eq!(entries, ["dangling.salty", "plain.txt"]);
    }

    #[test]
    #[cfg(unix)]
    fn test_update_rejects_hardlink_alias_of_output_path() {
        let temp_dir = TempDir::new().unwrap();
        let plain_path = temp_dir.path().join("plain.txt");
        let crypt_path = temp_dir.path().join("crypt.txt.saltybox");
        let hardlink_path = temp_dir.path().join("crypt-hardlink.saltybox");

        let original = b"Initial content";
        fs::write(&plain_path, original).unwrap();

        let mut reader = ConstantPassphraseReader::new(b"test password".to_vec());
        encrypt_with_default_engine(&plain_path, &crypt_path, &mut reader).unwrap();

        // A hardlink canonicalizes to its own path, so only the inode check
        // can catch this alias.
        fs::hard_link(&crypt_path, &hardlink_path).unwrap();

        let mut reader = ConstantPassphraseReader::new(b"test password".to_vec());
        let result = update_with_default_engine(&hardlink_path, &crypt_path, &mut reader);

        let err = result.expect_err("expected hardlink path conflict failure");
        assert_eq!(err.category, ErrorCategory::User);
        assert_eq!(err.kind, Some(ErrorKind::Io));
        assert_eq!(
            err.message(),
            "input and output paths must be different for update"
        );

        let decrypted_path = temp_dir.path().join("decrypted.txt");
        let mut reader = ConstantPassphraseReader::new(b"test password".to_vec());
        decrypt_file(&crypt_path, &decrypted_path, &mut reader).unwrap();
        let decrypted = fs::read(&decrypted_path).unwrap();
        assert_eq!(decrypted, original);
    }

    #[test]
    fn test_update_with_wrong_passphrase_fails() {
        let temp_dir = TempDir::new().unwrap();
        let plain1_path = temp_dir.path().join("plain1.txt");
        let plain2_path = temp_dir.path().join("plain2.txt");
        let crypt_path = temp_dir.path().join("crypt.txt.saltybox");

        fs::write(&plain1_path, b"Initial").unwrap();
        let mut reader = ConstantPassphraseReader::new(b"correct password".to_vec());
        encrypt_with_default_engine(&plain1_path, &crypt_path, &mut reader).unwrap();

        fs::write(&plain2_path, b"Updated").unwrap();
        let mut reader = ConstantPassphraseReader::new(b"wrong password".to_vec());
        let result = update_with_default_engine(&plain2_path, &crypt_path, &mut reader);

        let err = result.expect_err("expected authentication failure");
        assert_eq!(err.kind, Some(ErrorKind::AuthenticationFailed));

        let decrypted_path = temp_dir.path().join("decrypted.txt");
        let mut reader = ConstantPassphraseReader::new(b"correct password".to_vec());
        decrypt_file(&crypt_path, &decrypted_path, &mut reader).unwrap();
        let decrypted = fs::read(&decrypted_path).unwrap();
        assert_eq!(decrypted, b"Initial");
    }

    #[test]
    #[cfg(unix)]
    fn test_file_permissions() {
        let temp_dir = TempDir::new().unwrap();
        let plain_path = temp_dir.path().join("plain.txt");
        let crypt_path = temp_dir.path().join("crypt.txt.saltybox");

        fs::write(&plain_path, b"test").unwrap();

        let mut reader = ConstantPassphraseReader::new(b"test".to_vec());
        encrypt_with_default_engine(&plain_path, &crypt_path, &mut reader).unwrap();

        let metadata = fs::metadata(&crypt_path).unwrap();
        let permissions = metadata.permissions();
        assert_eq!(permissions.mode() & 0o777, 0o600);
    }

    #[test]
    #[cfg(unix)]
    fn test_encrypt_overwrites_insecure_output_permissions() {
        let temp_dir = TempDir::new().unwrap();
        let plain_path = temp_dir.path().join("plain.txt");
        let crypt_path = temp_dir.path().join("crypt.txt.saltybox");

        fs::write(&plain_path, b"secret").unwrap();
        fs::write(&crypt_path, b"existing ciphertext").unwrap();
        let mut permissions = fs::metadata(&crypt_path).unwrap().permissions();
        permissions.set_mode(0o644);
        fs::set_permissions(&crypt_path, permissions).unwrap();

        let mut reader = ConstantPassphraseReader::new(b"test".to_vec());
        encrypt_with_default_engine(&plain_path, &crypt_path, &mut reader).unwrap();

        let metadata = fs::metadata(&crypt_path).unwrap();
        let permissions = metadata.permissions();
        assert_eq!(permissions.mode() & 0o777, 0o600);
    }

    #[test]
    #[cfg(unix)]
    fn test_decrypt_overwrites_insecure_output_permissions() {
        let temp_dir = TempDir::new().unwrap();
        let plain_path = temp_dir.path().join("plain.txt");
        let crypt_path = temp_dir.path().join("crypt.txt.saltybox");
        let decrypted_path = temp_dir.path().join("decrypted.txt");

        fs::write(&plain_path, b"secret").unwrap();

        let mut reader = ConstantPassphraseReader::new(b"test".to_vec());
        encrypt_with_default_engine(&plain_path, &crypt_path, &mut reader).unwrap();

        fs::write(&decrypted_path, b"old plaintext").unwrap();
        let mut permissions = fs::metadata(&decrypted_path).unwrap().permissions();
        permissions.set_mode(0o644);
        fs::set_permissions(&decrypted_path, permissions).unwrap();

        let mut reader = ConstantPassphraseReader::new(b"test".to_vec());
        decrypt_file(&crypt_path, &decrypted_path, &mut reader).unwrap();

        let metadata = fs::metadata(&decrypted_path).unwrap();
        let permissions = metadata.permissions();
        assert_eq!(permissions.mode() & 0o777, 0o600);
    }

    #[test]
    #[cfg(unix)]
    fn test_decrypt_write_failure_preserves_existing_output() {
        let temp_dir = TempDir::new().unwrap();
        let output_dir = temp_dir.path().join("output");
        let plain_path = temp_dir.path().join("plain.txt");
        let crypt_path = temp_dir.path().join("crypt.txt.saltybox");
        let decrypted_path = output_dir.join("decrypted.txt");

        fs::create_dir(&output_dir).unwrap();
        fs::write(&plain_path, b"secret").unwrap();
        fs::write(&decrypted_path, b"old plaintext").unwrap();

        let mut reader = ConstantPassphraseReader::new(b"test".to_vec());
        encrypt_with_default_engine(&plain_path, &crypt_path, &mut reader).unwrap();

        let original_permissions = fs::metadata(&output_dir).unwrap().permissions();
        let mut unwritable_permissions = original_permissions.clone();
        unwritable_permissions.set_mode(0o500);
        fs::set_permissions(&output_dir, unwritable_permissions).unwrap();

        let probe_path = output_dir.join("write-probe");
        if fs::write(&probe_path, b"probe").is_ok() {
            fs::set_permissions(&output_dir, original_permissions).unwrap();
            fs::remove_file(probe_path).unwrap();
            eprintln!("skipping write-failure assertion because this process can still write");
            return;
        }

        let mut reader = ConstantPassphraseReader::new(b"test".to_vec());
        let result = decrypt_file(&crypt_path, &decrypted_path, &mut reader);

        fs::set_permissions(&output_dir, original_permissions).unwrap();

        result.expect_err("expected decrypt output write to fail");
        assert_eq!(fs::read(&decrypted_path).unwrap(), b"old plaintext");
    }

    /// Pins the pre-write framing SPEC.md makes normative for failures
    /// before the tempfile exists: an output directory that cannot be opened
    /// (mode 0o000 here, so EACCES rather than the specially-handled
    /// NotFound) must be reported as a failure while preparing to write. The
    /// pre-fix message claimed the file had already been written, sending
    /// users hunting for output that never existed. (SPEC's "leave nothing
    /// behind" clause is not asserted here: with the directory unwritable,
    /// no implementation could leave anything behind, so such an assertion
    /// would be vacuous.)
    #[test]
    #[cfg(unix)]
    fn test_unopenable_output_directory_reports_pre_write_failure() {
        let temp_dir = TempDir::new().unwrap();
        let output_dir = temp_dir.path().join("output");
        let plain_path = temp_dir.path().join("plain.txt");
        let crypt_path = output_dir.join("crypt.txt.saltybox");

        fs::create_dir(&output_dir).unwrap();
        fs::write(&plain_path, b"secret").unwrap();

        let original_permissions = fs::metadata(&output_dir).unwrap().permissions();
        let mut unopenable_permissions = original_permissions.clone();
        unopenable_permissions.set_mode(0o000);
        fs::set_permissions(&output_dir, unopenable_permissions).unwrap();

        // Root ignores directory permissions; skip rather than assert a
        // failure that cannot happen (same pattern as the write-failure test
        // above).
        if fs::File::open(&output_dir).is_ok() {
            fs::set_permissions(&output_dir, original_permissions).unwrap();
            eprintln!(
                "skipping unopenable-directory assertion because this process can still open it"
            );
            return;
        }

        let mut reader = ConstantPassphraseReader::new(b"test".to_vec());
        let result = encrypt_with_default_engine(&plain_path, &crypt_path, &mut reader);

        fs::set_permissions(&output_dir, original_permissions).unwrap();

        let err = result.expect_err("expected unopenable output directory to fail");
        let mut found_pre_write_framing = false;
        let mut source: Option<&(dyn std::error::Error + 'static)> = Some(&err);
        while let Some(e) = source {
            let msg = e.to_string();
            assert!(
                !msg.contains("after writing"),
                "message must not claim a write happened: {msg}"
            );
            if msg.contains("while preparing to write") {
                found_pre_write_framing = true;
            }
            source = e.source();
        }
        assert!(
            found_pre_write_framing,
            "expected the pre-write framing in the error chain"
        );
    }

    /// Pins the tempfile contract SPEC.md makes normative: the temporary file
    /// is created in the output directory, named with the `.saltybox-` prefix
    /// and `.tmp` suffix, and on Unix is owner-only from the start. A tempfile
    /// left behind by a crash must be recognizable by name, and must not be
    /// readable by other users while it holds plaintext.
    #[test]
    fn test_create_tempfile_is_private_and_named_per_spec() {
        let temp_dir = TempDir::new().unwrap();
        let output = OutputDestination::resolve(&temp_dir.path().join("output")).unwrap();
        let temp_file = output.create_tempfile().unwrap();
        let path = temp_file.path();

        assert_eq!(
            fs::canonicalize(path.parent().unwrap()).unwrap(),
            fs::canonicalize(temp_dir.path()).unwrap()
        );
        let name = path.file_name().unwrap().to_str().unwrap();
        assert!(name.starts_with(".saltybox-"), "name: {name}");
        assert!(name.ends_with(".tmp"), "name: {name}");
        #[cfg(unix)]
        {
            let mode = fs::metadata(path).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600, "tempfile must be owner-only");
        }
    }

    /// A failed rename onto the output path is a user error and leaves no
    /// tempfile behind, even while the caller still holds the error.
    ///
    /// SPEC.md classifies failures on user-supplied paths as user errors and
    /// promises that failures the command detects after creating the
    /// tempfile remove it; for `decrypt` a leftover would be a stray
    /// plaintext copy. The directory is inspected while `err` is alive on
    /// purpose: removal must happen at the failure site, not whenever the
    /// error's owner drops it. Making a directory at the basename after
    /// preparing the destination forces rename to fail. The check compares the directory's
    /// full contents so it does not depend on the tempfile naming scheme.
    #[test]
    fn test_failed_rename_removes_tempfile_and_is_user_error() {
        let temp_dir = TempDir::new().unwrap();
        let crypt_path = temp_dir.path().join("occupied");

        let destination = OutputDestination::resolve(&crypt_path).unwrap();
        let tempfile = destination.create_tempfile().unwrap();
        fs::create_dir(&crypt_path).unwrap();

        let err = rename_tempfile(&destination, tempfile)
            .expect_err("expected rename onto a directory to fail");

        assert_eq!(err.category, ErrorCategory::User);
        assert_eq!(err.kind, Some(ErrorKind::Io));
        let mut chain = String::new();
        let mut source: Option<&(dyn std::error::Error + 'static)> = Some(&err);
        while let Some(e) = source {
            chain.push_str(&e.to_string());
            chain.push('\n');
            source = e.source();
        }
        assert!(
            chain.contains("failed to rename to target file"),
            "chain: {chain}"
        );
        let mut entries: Vec<_> = fs::read_dir(temp_dir.path())
            .unwrap()
            .map(|entry| entry.unwrap().file_name().into_string().unwrap())
            .collect();
        entries.sort();
        assert_eq!(entries, ["occupied"]);
    }

    /// A destination that changes after staging must be preserved. Exercise
    /// the production publication step so the first save check cannot mask
    /// a missing final identity check.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn test_publication_rechecks_the_destination_and_removes_the_tempfile() {
        let temp = TempDir::new().unwrap();
        let output = temp.path().join("output");
        let replacement = temp.path().join("replacement");
        fs::write(&output, b"original").unwrap();
        let destination = OutputDestination::resolve(&output).unwrap();
        let original = destination.open_existing().unwrap();
        let mut tempfile = destination.create_tempfile().unwrap();
        fill_tempfile(&mut tempfile, &output, b"staged").unwrap();
        fs::write(&replacement, b"keep me").unwrap();
        fs::rename(&replacement, &output).unwrap();

        let err = publish_tempfile(&destination, tempfile, Some(&original)).unwrap_err();
        assert_eq!(err.category, ErrorCategory::User);
        assert!(err.message().contains("changed while preparing the update"));
        assert_eq!(fs::read(&output).unwrap(), b"keep me");
        assert_eq!(fs::read_dir(temp.path()).unwrap().count(), 1);
    }

    /// When removing the tempfile after a failure itself fails, the error
    /// names the leftover file so the user can remove it by hand.
    ///
    /// This is the only way a tempfile outlives an in-process failure, and
    /// for `decrypt` it holds plaintext, so SPEC.md requires the path to be
    /// reported rather than dropped. Removal is made to fail by taking write
    /// permission away from the directory holding the tempfile. Move that
    /// directory first to verify the error locates the file even after the
    /// original path becomes stale. The original failure remains the cause.
    #[test]
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    fn test_discard_tempfile_reports_failed_removal() {
        let temp_dir = TempDir::new().unwrap();
        let dir = temp_dir.path().join("locked");
        fs::create_dir(&dir).unwrap();
        let destination = OutputDestination::resolve(&dir.join("output")).unwrap();
        let temp_file = destination.create_tempfile().unwrap();
        let moved = temp_dir.path().join("moved\x1b");
        fs::rename(&dir, &moved).unwrap();
        let dir = fs::canonicalize(moved).unwrap();
        let tempfile_path = dir.join(temp_file.path().file_name().unwrap());

        let original_permissions = fs::metadata(&dir).unwrap().permissions();
        let mut locked_permissions = original_permissions.clone();
        locked_permissions.set_mode(0o500);
        fs::set_permissions(&dir, locked_permissions).unwrap();

        // Root ignores directory permissions; skip rather than assert a
        // failure that cannot happen (same pattern as the tests above).
        let probe = dir.join("probe");
        if fs::write(&probe, b"").is_ok() {
            fs::remove_file(&probe).unwrap();
            fs::set_permissions(&dir, original_permissions).unwrap();
            eprintln!("skipping failed-removal assertion because this process can still write");
            return;
        }

        let original = SaltyboxError::with_kind(
            ErrorCategory::Internal,
            ErrorKind::Io,
            "failed to sync out.txt",
        );
        let err = discard_tempfile(&destination, temp_file, original);
        fs::set_permissions(&dir, original_permissions).unwrap();

        let msg = err.to_string();
        assert!(msg.contains(&format!("{tempfile_path:?}")), "msg: {msg}");
        assert!(!msg.contains('\x1b'), "msg: {msg:?}");
        assert!(msg.contains("Remove it by hand"), "msg: {msg}");
        assert_eq!(err.category, ErrorCategory::Internal);
        let cause = std::error::Error::source(&err).expect("original failure as cause");
        assert_eq!(cause.to_string(), "failed to sync out.txt");
        assert!(tempfile_path.exists(), "the file should still be there");
    }

    /// A tempfile that is already gone when cleanup runs counts as removed:
    /// reporting a leftover that does not exist would send the user looking
    /// for a plaintext copy that is not there.
    #[test]
    fn test_discard_tempfile_treats_missing_file_as_removed() {
        let temp_dir = TempDir::new().unwrap();
        let destination = OutputDestination::resolve(&temp_dir.path().join("output")).unwrap();
        let temp_file = NamedTempFile::new_in(temp_dir.path()).unwrap();
        fs::remove_file(temp_file.path()).unwrap();

        let original = SaltyboxError::with_kind(
            ErrorCategory::Internal,
            ErrorKind::Io,
            "failed to write out.txt",
        );
        let err = discard_tempfile(&destination, temp_file, original);

        assert_eq!(err.to_string(), "failed to write out.txt");
        assert!(std::error::Error::source(&err).is_none());
    }

    /// An empty output path is rejected by name as a user error, with the
    /// unset-shell-variable hint, before anything is written.
    ///
    /// The realistic way to get here is `-o "$OUT"` with the variable unset,
    /// the same mistake SPEC.md calls out for empty passphrases, and SPEC.md
    /// promises the rejection says so. Before the dedicated check the empty
    /// path fell through to the parent-directory lookup and was reported as
    /// "no parent directory", a description of the mechanism rather than the
    /// mistake. That nothing is written is not asserted: an empty path has
    /// no directory to inspect short of the process working directory, and
    /// the check runs before any tempfile is created.
    #[test]
    fn test_encrypt_to_empty_output_path_is_user_error() {
        let temp_dir = TempDir::new().unwrap();
        let plain_path = temp_dir.path().join("plain.txt");
        fs::write(&plain_path, b"secret").unwrap();

        let mut reader = ConstantPassphraseReader::new(b"test".to_vec());
        let result = encrypt_with_default_engine(&plain_path, Path::new(""), &mut reader);

        let err = result.expect_err("expected empty output path failure");
        assert_eq!(err.category, ErrorCategory::User);
        assert_eq!(err.kind, Some(ErrorKind::Io));
        let mut found = false;
        let mut source: Option<&(dyn std::error::Error + 'static)> = Some(&err);
        while let Some(e) = source {
            if e.to_string()
                == "empty output path is not allowed (note that an unset shell variable expands to empty)"
            {
                found = true;
            }
            source = e.source();
        }
        assert!(
            found,
            "expected the empty-output-path diagnostic in the chain: {err}"
        );
    }

    /// An output path ending in a separator is rejected by the up-front path
    /// check, before any output-path I/O or tempfile creation, for `encrypt`.
    ///
    /// `Path::parent` ignores the trailing separator, so without the check
    /// `nodir/` resolved its directory to the path's parent, created a
    /// tempfile holding the output (plaintext, for `decrypt`) there, and only
    /// failed at the rename with an error that did not name the cause. The
    /// tempfile cleanup would also leave no tempfile behind, so the absence of
    /// a source error is what proves the rejection happens up front rather
    /// than at the failed rename. The path lives under a scratch directory so
    /// the test never touches the process working directory.
    #[test]
    fn test_encrypt_to_path_ending_in_separator_is_rejected_up_front() {
        let temp_dir = TempDir::new().unwrap();
        let plain_path = temp_dir.path().join("plain.txt");
        fs::write(&plain_path, b"secret").unwrap();
        let crypt_path = temp_dir.path().join("nodir/");

        let mut reader = ConstantPassphraseReader::new(b"test".to_vec());
        let err = encrypt_with_default_engine(&plain_path, &crypt_path, &mut reader)
            .expect_err("expected trailing-separator output path failure");

        assert_eq!(err.category, ErrorCategory::User);
        assert_eq!(err.kind, Some(ErrorKind::Io));
        assert!(
            err.to_string().contains("ends in a path separator"),
            "msg: {err}"
        );
        assert!(
            std::error::Error::source(&err).is_none(),
            "rejected by the path check, not by a failed I/O call"
        );
        let entries: Vec<_> = fs::read_dir(temp_dir.path())
            .unwrap()
            .map(|entry| entry.unwrap().file_name().into_string().unwrap())
            .collect();
        assert_eq!(entries, ["plain.txt"]);
    }

    /// Every command rejects a bad output path before it reads its input or
    /// asks for a passphrase.
    ///
    /// The path check only looks at the argument, so it runs first: a bad
    /// `-o` must not make the user type a passphrase and wait out key
    /// derivation first. The input path here does not exist, so a read before
    /// the check would surface as a read error instead, and the reader panics
    /// if asked for a passphrase. Exercise the empty path, a trailing
    /// separator, and final dot components through all three commands.
    #[test]
    fn test_bad_output_path_is_rejected_before_input_read_and_prompt() {
        struct PanickingReader;
        impl PassphraseReader for PanickingReader {
            fn read_passphrase(&mut self) -> Result<Zeroizing<Vec<u8>>> {
                panic!("the passphrase must not be requested before the output path is checked");
            }
        }

        let temp_dir = TempDir::new().unwrap();
        let missing_input = temp_dir.path().join("missing-input");
        let trailing = temp_dir.path().join("nodir/");
        let directory = temp_dir.path().join("dir");
        fs::create_dir(&directory).unwrap();
        let dot = directory.join(".");
        let dot_dot = directory.join("..");
        for (output, expected) in [
            (Path::new(""), "empty output path is not allowed"),
            (trailing.as_path(), "ends in a path separator"),
            (Path::new("."), "ends in '.' or '..'"),
            (Path::new(".."), "ends in '.' or '..'"),
            (dot.as_path(), "ends in '.' or '..'"),
            (dot_dot.as_path(), "ends in '.' or '..'"),
        ] {
            let results = [
                encrypt_with_default_engine(&missing_input, output, &mut PanickingReader),
                decrypt_file(&missing_input, output, &mut PanickingReader),
                update_with_default_engine(&missing_input, output, &mut PanickingReader),
            ];
            for result in results {
                let err = result.expect_err("expected output path rejection");
                assert!(err.to_string().contains(expected), "msg: {err}");
                assert!(std::error::Error::source(&err).is_none());
            }
        }
        assert_eq!(fs::read_dir(directory).unwrap().count(), 0);
        assert_eq!(fs::read_dir(temp_dir.path()).unwrap().count(), 1);
    }

    /// `update` rejects an output path ending in a separator with the same
    /// specific message, instead of failing first on reading the existing
    /// file (which is what happened before it ran the path check itself).
    /// SPEC.md promises the rejection for every command.
    #[test]
    fn test_update_to_path_ending_in_separator_is_rejected_up_front() {
        let temp_dir = TempDir::new().unwrap();
        let plain_path = temp_dir.path().join("plain.txt");
        fs::write(&plain_path, b"secret").unwrap();
        let crypt_path = temp_dir.path().join("nodir/");

        let mut reader = ConstantPassphraseReader::new(b"test".to_vec());
        let err = update_with_default_engine(&plain_path, &crypt_path, &mut reader)
            .expect_err("expected trailing-separator output path failure");

        assert_eq!(err.category, ErrorCategory::User);
        assert_eq!(err.kind, Some(ErrorKind::Io));
        assert!(
            err.to_string().contains("ends in a path separator"),
            "msg: {err}"
        );
        assert!(std::error::Error::source(&err).is_none());
    }

    /// `update` rejects an empty output path with the empty-path message
    /// rather than a generic error from reading "" as the existing file.
    /// SPEC.md promises that rejection for every command; this pins that
    /// `update` runs the path check before its read.
    #[test]
    fn test_update_to_empty_output_path_is_rejected_up_front() {
        let temp_dir = TempDir::new().unwrap();
        let plain_path = temp_dir.path().join("plain.txt");
        fs::write(&plain_path, b"secret").unwrap();

        let mut reader = ConstantPassphraseReader::new(b"test".to_vec());
        let err = update_with_default_engine(&plain_path, Path::new(""), &mut reader)
            .expect_err("expected empty output path failure");

        assert_eq!(err.category, ErrorCategory::User);
        assert_eq!(err.kind, Some(ErrorKind::Io));
        assert!(
            err.to_string().contains("empty output path is not allowed"),
            "msg: {err}"
        );
        assert!(std::error::Error::source(&err).is_none());
    }

    /// A typoed output directory is a user error, and on Unix the message
    /// names the directory and says it does not exist.
    ///
    /// SPEC.md promises a nonexistent output directory "is reported as such",
    /// which is a promise about the wording: the classification alone would
    /// still hold if the specific pre-check regressed to the generic
    /// tempfile-creation failure, and only the message assertion catches
    /// that. The wording comes from the Unix-only directory open that runs
    /// before anything is written, hence the gate; Windows is unsupported.
    #[test]
    fn test_encrypt_to_missing_output_directory_is_user_error() {
        let temp_dir = TempDir::new().unwrap();
        let plain_path = temp_dir.path().join("plain.txt");
        let output_dir = temp_dir.path().join("no-such-dir");
        let crypt_path = output_dir.join("crypt.txt.saltybox");

        fs::write(&plain_path, b"secret").unwrap();

        let mut reader = ConstantPassphraseReader::new(b"test".to_vec());
        let result = encrypt_with_default_engine(&plain_path, &crypt_path, &mut reader);

        let err = result.expect_err("expected missing output directory failure");
        assert_eq!(err.category, ErrorCategory::User);
        assert_eq!(err.kind, Some(ErrorKind::Io));

        // On macOS the runner's /var pathname can resolve through /private.
        // The diagnostic names the missing directory on the resolved route.
        #[cfg(unix)]
        {
            #[cfg(any(target_os = "linux", target_os = "macos"))]
            let output_dir = fs::canonicalize(temp_dir.path())
                .unwrap()
                .join("no-such-dir");
            let expected = format!("output directory {output_dir:?} does not exist");
            let mut source: Option<&(dyn std::error::Error + 'static)> = Some(&err);
            let mut found = false;
            while let Some(e) = source {
                if e.to_string() == expected {
                    found = true;
                }
                source = e.source();
            }
            assert!(found, "expected {expected:?} in the error chain: {err}");
        }
    }

    /// A directory given as the input file is a user error, not internal.
    ///
    /// Reading a directory fails with something other than NotFound, so this
    /// pins the half of SPEC.md's rule the nonexistent-input test does not:
    /// every I/O failure on a user-supplied path is the user's, not just a
    /// missing file. Before the rule, only NotFound was classified User and
    /// this case was Internal. The CLI-level test cannot observe the
    /// category; both produce the same nonzero exit.
    #[test]
    fn test_read_of_directory_as_input_is_user_error() {
        let temp_dir = TempDir::new().unwrap();
        let decrypted_path = temp_dir.path().join("decrypted.txt");

        let mut reader = ConstantPassphraseReader::new(b"test".to_vec());
        let result = decrypt_file(temp_dir.path(), &decrypted_path, &mut reader);

        let err = result.expect_err("expected directory-as-input failure");
        assert_eq!(err.category, ErrorCategory::User);
        assert_eq!(err.kind, Some(ErrorKind::Io));
        assert!(!decrypted_path.exists());
    }

    #[test]
    fn test_read_of_nonexistent_input_is_user_error() {
        // Pins the NotFound half of SPEC.md's rule that I/O failures on
        // user-supplied paths are user errors: a typoed input path is a user
        // mistake, not an internal failure. The CLI-level test cannot
        // observe the category; both produce the same nonzero exit.
        let temp_dir = TempDir::new().unwrap();
        let missing_path = temp_dir.path().join("no-such-file.saltybox");
        let decrypted_path = temp_dir.path().join("decrypted.txt");

        let mut reader = ConstantPassphraseReader::new(b"test".to_vec());
        let result = decrypt_file(&missing_path, &decrypted_path, &mut reader);

        let err = result.expect_err("expected missing input file failure");
        assert_eq!(err.category, ErrorCategory::User);
        assert_eq!(err.kind, Some(ErrorKind::Io));
        assert!(!decrypted_path.exists());
    }

    #[test]
    fn test_decrypt_wrong_passphrase() {
        let temp_dir = TempDir::new().unwrap();
        let plain_path = temp_dir.path().join("plain.txt");
        let crypt_path = temp_dir.path().join("crypt.txt.saltybox");
        let decrypted_path = temp_dir.path().join("decrypted.txt");

        fs::write(&plain_path, b"secret").unwrap();

        let mut reader = ConstantPassphraseReader::new(b"correct".to_vec());
        encrypt_with_default_engine(&plain_path, &crypt_path, &mut reader).unwrap();

        let mut reader = ConstantPassphraseReader::new(b"wrong".to_vec());
        let result = decrypt_file(&crypt_path, &decrypted_path, &mut reader);

        assert!(result.is_err());
        assert!(!decrypted_path.exists());
    }

    #[test]
    fn test_decrypt_wrong_passphrase_preserves_existing_output() {
        let temp_dir = TempDir::new().unwrap();
        let plain_path = temp_dir.path().join("plain.txt");
        let crypt_path = temp_dir.path().join("crypt.txt.saltybox");
        let decrypted_path = temp_dir.path().join("decrypted.txt");

        fs::write(&plain_path, b"secret").unwrap();
        fs::write(&decrypted_path, b"old plaintext").unwrap();

        let mut reader = ConstantPassphraseReader::new(b"correct".to_vec());
        encrypt_with_default_engine(&plain_path, &crypt_path, &mut reader).unwrap();

        let mut reader = ConstantPassphraseReader::new(b"wrong".to_vec());
        assert!(decrypt_file(&crypt_path, &decrypted_path, &mut reader).is_err());
        assert_eq!(fs::read(&decrypted_path).unwrap(), b"old plaintext");
    }

    /// Input that is not valid UTF-8 is rejected before any format
    /// interpretation (SPEC.md), tagged as an armoring error: the read itself
    /// succeeded, and what failed is the armor's requirement that the file
    /// be text. Tagging it as I/O would misdescribe it as a filesystem
    /// problem.
    #[test]
    fn test_decrypt_rejects_non_utf8_armored_input() {
        let temp_dir = TempDir::new().unwrap();
        let crypt_path = temp_dir.path().join("crypt.txt.saltybox");
        let decrypted_path = temp_dir.path().join("decrypted.txt");

        fs::write(&crypt_path, [0xff]).unwrap();

        let mut reader = ConstantPassphraseReader::new(b"test".to_vec());
        let result = decrypt_file(&crypt_path, &decrypted_path, &mut reader);

        let err = result.expect_err("expected UTF-8 rejection");
        assert_eq!(err.category, ErrorCategory::User);
        assert_eq!(err.kind, Some(ErrorKind::ArmoringInvalid));
        assert_eq!(err.message(), "input file is not valid UTF-8");
        assert!(!decrypted_path.exists());
    }

    /// `update` rejects an existing file that is not valid UTF-8 the same way
    /// `decrypt` does, as an armoring error, and leaves the file unchanged.
    /// SPEC.md promises that `update`'s validation read classifies failures
    /// exactly as `decrypt` does and leaves the existing file unchanged on
    /// failure; this pins the non-UTF-8 case.
    #[test]
    fn test_update_rejects_non_utf8_encrypted_input() {
        let temp_dir = TempDir::new().unwrap();
        let plain_path = temp_dir.path().join("plain.txt");
        let crypt_path = temp_dir.path().join("crypt.txt.saltybox");

        fs::write(&plain_path, b"new plaintext").unwrap();
        fs::write(&crypt_path, [0xff]).unwrap();

        let mut reader = ConstantPassphraseReader::new(b"test".to_vec());
        let result = update_with_default_engine(&plain_path, &crypt_path, &mut reader);

        let err = result.expect_err("expected UTF-8 rejection");
        assert_eq!(err.category, ErrorCategory::User);
        assert_eq!(err.kind, Some(ErrorKind::ArmoringInvalid));
        assert_eq!(err.message(), "encrypted file is not valid UTF-8");
        assert_eq!(fs::read(&crypt_path).unwrap(), [0xff]);
    }

    /// A structurally malformed existing ciphertext aborts `update` with the
    /// same format diagnostic `decrypt` would give, and the file's bytes are
    /// left exactly as they were.
    ///
    /// SPEC.md promises that the validation read fails in the same scenarios
    /// as `decrypt`, with the same classifications, and that any such failure
    /// leaves the existing file unchanged. The wrong-passphrase and non-UTF-8
    /// tests pin two of those scenarios; this one pins the format-error class,
    /// which is otherwise only tested through `decrypt`. Uses a real
    /// ciphertext with its `:end` marker cut off so the input is valid UTF-8
    /// and reaches the armor check rather than failing earlier.
    #[test]
    fn test_update_rejects_malformed_encrypted_input_unchanged() {
        let temp_dir = TempDir::new().unwrap();
        let plain_path = temp_dir.path().join("plain.txt");
        let crypt_path = temp_dir.path().join("crypt.txt.saltybox");

        fs::write(&plain_path, b"Initial").unwrap();
        let mut reader = ConstantPassphraseReader::new(b"test".to_vec());
        encrypt_with_default_engine(&plain_path, &crypt_path, &mut reader).unwrap();

        let armored = fs::read_to_string(&crypt_path).unwrap();
        let truncated = armored
            .strip_suffix(":end")
            .expect("default engine output ends with the v2 marker");
        fs::write(&crypt_path, truncated).unwrap();

        fs::write(&plain_path, b"Updated").unwrap();
        let mut reader = ConstantPassphraseReader::new(b"test".to_vec());
        let result = update_with_default_engine(&plain_path, &crypt_path, &mut reader);

        let err = result.expect_err("expected armor rejection");
        assert_eq!(err.category, ErrorCategory::User);
        assert_eq!(err.kind, Some(ErrorKind::ArmoringInvalid));
        assert_eq!(fs::read_to_string(&crypt_path).unwrap(), truncated);
    }

    /// `update` validates the passphrase against the existing file BEFORE it
    /// reads the new plaintext: with a wrong passphrase and a missing
    /// plaintext file, the error is the authentication failure, not the I/O
    /// error.
    ///
    /// SPEC.md describes `update` as "validating first", and the order is
    /// user-visible only when both steps would fail. Nothing else in the
    /// suite would notice the two reads being swapped. Paired with
    /// `test_update_missing_plaintext_after_validation_leaves_file_unchanged`,
    /// which covers the correct-passphrase side of the same ordering.
    #[test]
    fn test_update_validates_passphrase_before_reading_plaintext() {
        let temp_dir = TempDir::new().unwrap();
        let plain_path = temp_dir.path().join("plain.txt");
        let missing_path = temp_dir.path().join("missing.txt");
        let crypt_path = temp_dir.path().join("crypt.txt.saltybox");

        fs::write(&plain_path, b"Initial").unwrap();
        let mut reader = ConstantPassphraseReader::new(b"correct password".to_vec());
        encrypt_with_default_engine(&plain_path, &crypt_path, &mut reader).unwrap();

        let mut reader = ConstantPassphraseReader::new(b"wrong password".to_vec());
        let result = update_with_default_engine(&missing_path, &crypt_path, &mut reader);

        let err = result.expect_err("expected authentication failure before plaintext read");
        assert_eq!(err.kind, Some(ErrorKind::AuthenticationFailed));
    }

    /// A missing new-plaintext file, discovered after the passphrase has
    /// validated, is a user I/O error and leaves the existing ciphertext
    /// byte-for-byte unchanged.
    ///
    /// This is the point in `update` where validation has succeeded and the
    /// only remaining failure is the user's own input path. The existing file
    /// must not be touched: the write happens only after the new plaintext is
    /// in hand. Companion to
    /// `test_update_validates_passphrase_before_reading_plaintext`.
    #[test]
    fn test_update_missing_plaintext_after_validation_leaves_file_unchanged() {
        let temp_dir = TempDir::new().unwrap();
        let plain_path = temp_dir.path().join("plain.txt");
        let missing_path = temp_dir.path().join("missing.txt");
        let crypt_path = temp_dir.path().join("crypt.txt.saltybox");

        fs::write(&plain_path, b"Initial").unwrap();
        let mut reader = ConstantPassphraseReader::new(b"correct password".to_vec());
        encrypt_with_default_engine(&plain_path, &crypt_path, &mut reader).unwrap();
        let before = fs::read(&crypt_path).unwrap();

        let mut reader = ConstantPassphraseReader::new(b"correct password".to_vec());
        let result = update_with_default_engine(&missing_path, &crypt_path, &mut reader);

        let err = result.expect_err("expected missing plaintext failure");
        assert_eq!(err.category, ErrorCategory::User);
        assert_eq!(err.kind, Some(ErrorKind::Io));
        assert_eq!(fs::read(&crypt_path).unwrap(), before);
    }

    /// Empty passphrases and passphrases containing a line break are
    /// rejected by every operation, including decrypt and update.
    ///
    /// Both are almost always a piping mistake (`echo -n "$PASS"` or
    /// `echo "$PASS"` with `PASS` unset). SPEC.md rejects them for every
    /// command, which deliberately makes files encrypted with such a
    /// passphrase by older versions undecryptable. `\r` is included so
    /// Windows-style line endings are caught, and line breaks are rejected
    /// wherever they appear, not just at the end.
    #[test]
    fn test_invalid_passphrases_are_rejected_by_all_operations() {
        let temp_dir = TempDir::new().unwrap();
        let plain_path = temp_dir.path().join("plain.txt");
        let crypt_path = temp_dir.path().join("crypt.txt.saltybox");
        let decrypted_path = temp_dir.path().join("decrypted.txt");
        fs::write(&plain_path, b"secret").unwrap();

        let cases: &[(&[u8], ErrorKind)] = &[
            (b"", ErrorKind::EmptyPassphrase),
            (b"\n", ErrorKind::PassphraseContainsLineBreak),
            (b"pw\n", ErrorKind::PassphraseContainsLineBreak),
            (b"pw\r\n", ErrorKind::PassphraseContainsLineBreak),
            (b"pw\r", ErrorKind::PassphraseContainsLineBreak),
            (b"p\nw", ErrorKind::PassphraseContainsLineBreak),
        ];
        for &(passphrase, kind) in cases {
            let mut reader = ConstantPassphraseReader::new(passphrase.to_vec());
            let err = encrypt_with_default_engine(&plain_path, &crypt_path, &mut reader)
                .expect_err("expected rejection on encrypt");
            assert_eq!(err.category, ErrorCategory::User);
            assert_eq!(err.kind, Some(kind), "encrypt, passphrase {passphrase:?}");
            assert!(!crypt_path.exists());
        }

        // A real encrypted file, so decrypt and update fail on the
        // passphrase check rather than on a missing input.
        let mut reader = ConstantPassphraseReader::new(b"real passphrase".to_vec());
        encrypt_with_default_engine(&plain_path, &crypt_path, &mut reader).unwrap();
        let existing = fs::read(&crypt_path).unwrap();
        for &(passphrase, kind) in cases {
            let mut reader = ConstantPassphraseReader::new(passphrase.to_vec());
            let err = decrypt_file(&crypt_path, &decrypted_path, &mut reader)
                .expect_err("expected rejection on decrypt");
            assert_eq!(err.category, ErrorCategory::User);
            assert_eq!(err.kind, Some(kind), "decrypt, passphrase {passphrase:?}");
            assert!(!decrypted_path.exists());

            let mut reader = ConstantPassphraseReader::new(passphrase.to_vec());
            let err = update_with_default_engine(&plain_path, &crypt_path, &mut reader)
                .expect_err("expected rejection on update");
            assert_eq!(err.category, ErrorCategory::User);
            assert_eq!(err.kind, Some(kind), "update, passphrase {passphrase:?}");
            assert_eq!(fs::read(&crypt_path).unwrap(), existing);
        }
    }

    /// An interactively confirmed passphrase whose two entries differ makes
    /// `encrypt` fail as a user error and write nothing.
    ///
    /// The terminal prompt reads with echo disabled, so without the second
    /// entry a typo would silently become the passphrase of a file nobody can
    /// decrypt, found out only when decryption fails. SPEC.md requires the
    /// confirmation for interactive `encrypt`.
    #[test]
    fn test_encrypt_rejects_mismatched_confirmation() {
        let temp_dir = TempDir::new().unwrap();
        let plain_path = temp_dir.path().join("plain.txt");
        let crypt_path = temp_dir.path().join("crypt.txt.saltybox");
        fs::write(&plain_path, b"secret").unwrap();

        let mut reader =
            ConfirmingPassphraseReader::new(b"correct horse".to_vec(), b"correct hose".to_vec());
        let err = encrypt_with_default_engine(&plain_path, &crypt_path, &mut reader)
            .expect_err("expected mismatched confirmation to fail");

        assert_eq!(err.category, ErrorCategory::User);
        assert_eq!(err.kind, Some(ErrorKind::PassphraseConfirmationMismatch));
        assert_eq!(
            err.message(),
            "passphrase entries do not match; nothing was written"
        );
        assert!(!crypt_path.exists());
    }

    /// A matching confirmation lets `encrypt` proceed, and the file decrypts
    /// with that passphrase. This guards against the confirmation step
    /// rejecting, or altering, a correctly repeated passphrase.
    #[test]
    fn test_encrypt_accepts_matching_confirmation() {
        let temp_dir = TempDir::new().unwrap();
        let plain_path = temp_dir.path().join("plain.txt");
        let crypt_path = temp_dir.path().join("crypt.txt.saltybox");
        let decrypted_path = temp_dir.path().join("decrypted.txt");
        fs::write(&plain_path, b"secret").unwrap();

        let mut reader =
            ConfirmingPassphraseReader::new(b"correct horse".to_vec(), b"correct horse".to_vec());
        encrypt_with_default_engine(&plain_path, &crypt_path, &mut reader).unwrap();

        let mut reader = ConstantPassphraseReader::new(b"correct horse".to_vec());
        decrypt_file(&crypt_path, &decrypted_path, &mut reader).unwrap();
        assert_eq!(fs::read(&decrypted_path).unwrap(), b"secret");
    }

    /// `decrypt` and `update` never ask for a confirmation: the existing file
    /// already confirms the passphrase there, and SPEC.md rules out a second
    /// prompt. The reader panics if asked, so a regression that asked (which
    /// interactively means a surprise second prompt) fails the test.
    #[test]
    fn test_decrypt_and_update_do_not_confirm() {
        struct NoConfirmReader;
        impl PassphraseReader for NoConfirmReader {
            fn read_passphrase(&mut self) -> Result<Zeroizing<Vec<u8>>> {
                Ok(Zeroizing::new(b"pw".to_vec()))
            }
            fn read_confirmation(&mut self) -> Result<Option<Zeroizing<Vec<u8>>>> {
                panic!("decrypt and update must not ask for a confirmation");
            }
        }

        let temp_dir = TempDir::new().unwrap();
        let plain_path = temp_dir.path().join("plain.txt");
        let crypt_path = temp_dir.path().join("crypt.txt.saltybox");
        let decrypted_path = temp_dir.path().join("decrypted.txt");
        fs::write(&plain_path, b"secret").unwrap();
        let mut reader = ConstantPassphraseReader::new(b"pw".to_vec());
        encrypt_with_default_engine(&plain_path, &crypt_path, &mut reader).unwrap();

        decrypt_file(&crypt_path, &decrypted_path, &mut NoConfirmReader).unwrap();
        update_with_default_engine(&plain_path, &crypt_path, &mut NoConfirmReader).unwrap();
    }

    #[test]
    fn test_empty_file() {
        let temp_dir = TempDir::new().unwrap();
        let plain_path = temp_dir.path().join("empty.txt");
        let crypt_path = temp_dir.path().join("empty.txt.saltybox");
        let decrypted_path = temp_dir.path().join("decrypted.txt");

        fs::write(&plain_path, b"").unwrap();

        let mut reader = ConstantPassphraseReader::new(b"test".to_vec());
        encrypt_with_default_engine(&plain_path, &crypt_path, &mut reader).unwrap();

        let mut reader = ConstantPassphraseReader::new(b"test".to_vec());
        decrypt_file(&crypt_path, &decrypted_path, &mut reader).unwrap();

        let decrypted = fs::read(&decrypted_path).unwrap();
        assert_eq!(decrypted, b"");
    }
}
