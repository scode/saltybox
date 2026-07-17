//! Passphrase reading functionality

use crate::error::{ErrorCategory, ErrorKind, Result, SaltyboxError};
use std::io::{self, IsTerminal, Read, Write};
use zeroize::Zeroizing;

/// Trait for reading passphrases from various sources
pub trait PassphraseReader {
    /// Read a passphrase as arbitrary bytes (not necessarily UTF-8).
    ///
    /// The returned buffer is wrapped in `Zeroizing`, which wipes it on drop.
    /// This is best-effort hardening against casual exposure (core dumps,
    /// swap, reused heap), not a guarantee that no copy of the passphrase
    /// remains in memory: an implementation cannot wipe copies made before
    /// the bytes reach the returned buffer — intermediate allocations,
    /// third-party library internals, kernel tty and pipe buffers. Each
    /// implementation documents what its wipe does and does not cover.
    fn read_passphrase(&mut self) -> Result<Zeroizing<Vec<u8>>>;
}

/// Returns a fixed passphrase (for testing)
#[cfg(test)]
pub struct ConstantPassphraseReader {
    passphrase: Zeroizing<Vec<u8>>,
}

#[cfg(test)]
impl ConstantPassphraseReader {
    pub fn new(passphrase: Vec<u8>) -> Self {
        Self {
            passphrase: Zeroizing::new(passphrase),
        }
    }
}

#[cfg(test)]
impl PassphraseReader for ConstantPassphraseReader {
    fn read_passphrase(&mut self) -> Result<Zeroizing<Vec<u8>>> {
        Ok(self.passphrase.clone())
    }
}

/// Pre-reserved capacity for the passphrase buffer.
///
/// `Zeroizing` only wipes the buffer the `Vec` holds at drop time. If
/// `read_to_end` outgrows the allocation, the old buffer is freed without
/// being wiped, stranding a passphrase prefix in freed heap. Reserving more
/// than any realistic passphrase up front means the buffer never grows, so
/// the drop-time wipe covers the only copy this process made. Longer input
/// still works — this is not a length limit — it merely degrades to the
/// best-effort behavior described on [`PassphraseReader`].
const PASSPHRASE_BUFFER_CAPACITY: usize = 4096;

/// Reads passphrase from any io::Read source
pub struct ReaderPassphraseReader {
    reader: Box<dyn Read>,
}

impl ReaderPassphraseReader {
    pub fn new(reader: Box<dyn Read>) -> Self {
        Self { reader }
    }
}

impl PassphraseReader for ReaderPassphraseReader {
    /// Reads all bytes until end-of-input.
    ///
    /// For input smaller than `PASSPHRASE_BUFFER_CAPACITY`, this
    /// implementation makes no unwiped copy of its own: `read_to_end` reads
    /// directly into the pre-reserved spare capacity without reallocating.
    /// What the wrapped reader does internally is outside this type's
    /// control — wrapping the source in a `BufReader`, for example, would
    /// stage bytes in a buffer that never gets wiped. The reader the CLI
    /// passes here is `std::io::stdin()`, whose `read_to_end` delegates to
    /// the underlying fd rather than staging bytes in its `BufReader`
    /// (verified against std's implementation as of Rust 1.93; if that
    /// drifts, the result is an unwiped copy, not incorrect behavior).
    /// Kernel pipe buffers hold a copy regardless.
    fn read_passphrase(&mut self) -> Result<Zeroizing<Vec<u8>>> {
        let mut data = Zeroizing::new(Vec::with_capacity(PASSPHRASE_BUFFER_CAPACITY));
        self.reader.read_to_end(&mut data).map_err(|e| {
            SaltyboxError::with_kind_and_source(
                ErrorCategory::Internal,
                ErrorKind::Io,
                "error reading passphrase",
                e,
            )
        })?;
        Ok(data)
    }
}

/// Reads passphrase from terminal with no echo
pub struct TerminalPassphraseReader;

impl PassphraseReader for TerminalPassphraseReader {
    /// Read passphrase from terminal.
    ///
    /// Note: Terminal input is limited to UTF-8 due to rpassword library constraints.
    /// For non-UTF-8 passphrases, use --passphrase-stdin instead.
    fn read_passphrase(&mut self) -> Result<Zeroizing<Vec<u8>>> {
        if !io::stdin().is_terminal() {
            return Err(SaltyboxError::with_kind(
                ErrorCategory::User,
                ErrorKind::PassphraseUnavailable,
                "cannot read passphrase from terminal - stdin is not a terminal",
            ));
        }

        io::stderr()
            .write_all(b"Passphrase (saltybox): ")
            .map_err(|e| {
                SaltyboxError::with_kind_and_source(
                    ErrorCategory::Internal,
                    ErrorKind::Io,
                    "failed to write prompt",
                    e,
                )
            })?;
        io::stderr().flush().map_err(|e| {
            SaltyboxError::with_kind_and_source(
                ErrorCategory::Internal,
                ErrorKind::Io,
                "failed to flush prompt",
                e,
            )
        })?;

        // Read without echo. rpassword returns a plain String; the
        // into_bytes below hands its buffer to Zeroizing without copying, so
        // the final buffer does get wiped — but any intermediate buffers
        // rpassword used while assembling the line are its own, and we
        // cannot wipe those.
        let passphrase = rpassword::read_password().map_err(|e| {
            SaltyboxError::with_kind_and_source(
                ErrorCategory::Internal,
                ErrorKind::PassphraseUnavailable,
                "failure reading passphrase",
                e,
            )
        })?;

        Ok(Zeroizing::new(passphrase.into_bytes()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_constant_reader() {
        let mut reader = ConstantPassphraseReader::new(b"test123".to_vec());
        assert_eq!(&*reader.read_passphrase().unwrap(), b"test123");
        assert_eq!(&*reader.read_passphrase().unwrap(), b"test123");
    }

    /// Tests the terminal reader. This is ignored by default and must be run
    /// explicitly and with human input:
    ///
    /// cargo test test_terminal_reader_interactive -- --ignored --nocapture
    #[test]
    #[ignore]
    fn test_terminal_reader_interactive() {
        let mut reader = TerminalPassphraseReader;
        println!("\nPlease enter a test passphrase:");
        let passphrase = reader.read_passphrase().unwrap();
        println!("You entered: {}", String::from_utf8_lossy(&passphrase));
        assert!(!passphrase.is_empty(), "Expected non-empty passphrase");
    }

    #[test]
    fn test_reader_passphrase_reader() {
        let data = b"mypassword";
        let mut reader = ReaderPassphraseReader::new(Box::new(&data[..]));
        assert_eq!(&*reader.read_passphrase().unwrap(), b"mypassword");
    }

    /// Readers pass an empty passphrase through unmodified: rejecting empty
    /// passphrases is the operation layer's job (see `file_ops`), so it holds
    /// for every reader implementation rather than being re-enforced (or
    /// forgotten) per source.
    #[test]
    fn test_reader_passphrase_reader_empty() {
        let data = b"";
        let mut reader = ReaderPassphraseReader::new(Box::new(&data[..]));
        assert_eq!(&*reader.read_passphrase().unwrap(), b"");
    }

    /// Guards the property the preallocation exists for: a realistic-size
    /// passphrase is read without growing the buffer, so the drop-time wipe
    /// covers the only copy this process makes. If the returned capacity is
    /// not the pre-reserved one, the buffer was reallocated and an unwiped
    /// prefix was stranded in freed heap — the bug the preallocation fixed.
    #[test]
    fn test_reader_passphrase_reader_small_input_does_not_reallocate() {
        let data = b"a realistic passphrase";
        let mut reader = ReaderPassphraseReader::new(Box::new(&data[..]));
        let passphrase = reader.read_passphrase().unwrap();
        assert_eq!(&**passphrase, data);
        assert_eq!(passphrase.capacity(), PASSPHRASE_BUFFER_CAPACITY);
    }

    /// Input larger than the pre-reserved buffer capacity must still be
    /// accepted: the preallocation is memory hygiene, not a length limit.
    #[test]
    fn test_reader_passphrase_reader_larger_than_prealloc() {
        let data = vec![0x42u8; PASSPHRASE_BUFFER_CAPACITY * 2];
        let mut reader = ReaderPassphraseReader::new(Box::new(std::io::Cursor::new(data.clone())));
        assert_eq!(&**reader.read_passphrase().unwrap(), &data[..]);
    }

    /// Verifies that ReaderPassphraseReader accepts arbitrary byte sequences,
    /// not just valid UTF-8. This enables --passphrase-stdin to work with
    /// passphrases containing non-UTF-8 bytes.
    #[test]
    fn test_reader_passphrase_reader_non_utf8() {
        let data: &[u8] = &[0xff, 0xfe, 0x00, 0x01];
        let mut reader = ReaderPassphraseReader::new(Box::new(data));
        assert_eq!(&*reader.read_passphrase().unwrap(), data);
    }
}
