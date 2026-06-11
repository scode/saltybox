//! Passphrase reading functionality

use crate::error::{ErrorCategory, ErrorKind, Result, SaltyboxError};
use std::io::{self, IsTerminal, Read, Write};
use zeroize::Zeroizing;

/// Trait for reading passphrases from various sources
pub trait PassphraseReader {
    /// Read a passphrase as arbitrary bytes (not necessarily UTF-8)
    ///
    /// Returns the passphrase wrapped in `Zeroizing` to ensure it is securely
    /// wiped from memory when dropped.
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
    fn read_passphrase(&mut self) -> Result<Zeroizing<Vec<u8>>> {
        let mut data = Zeroizing::new(Vec::new());
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

        // Read password *without echo*
        // Note: rpassword returns String (UTF-8 only), not zeroized
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

    #[test]
    fn test_reader_passphrase_reader_empty() {
        let data = b"";
        let mut reader = ReaderPassphraseReader::new(Box::new(&data[..]));
        assert_eq!(&*reader.read_passphrase().unwrap(), b"");
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
