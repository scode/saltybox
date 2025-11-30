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
pub struct ConstantPassphraseReader {
    passphrase: Zeroizing<Vec<u8>>,
}

impl ConstantPassphraseReader {
    pub fn new(passphrase: Vec<u8>) -> Self {
        Self {
            passphrase: Zeroizing::new(passphrase),
        }
    }
}

impl PassphraseReader for ConstantPassphraseReader {
    fn read_passphrase(&mut self) -> Result<Zeroizing<Vec<u8>>> {
        Ok(Zeroizing::new((*self.passphrase).clone()))
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
                format!("error reading passphrase: {}", e),
                e,
            )
        })?;
        Ok(data)
    }
}
/// Reads passphrase from terminal with no echo
pub struct TerminalPassphraseReader;

impl TerminalPassphraseReader {
    pub fn new() -> Self {
        Self
    }
}

impl Default for TerminalPassphraseReader {
    fn default() -> Self {
        Self::new()
    }
}

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
                    format!("failed to write prompt: {}", e),
                    e,
                )
            })?;
        io::stderr().flush().map_err(|e| {
            SaltyboxError::with_kind_and_source(
                ErrorCategory::Internal,
                ErrorKind::Io,
                format!("failed to flush prompt: {}", e),
                e,
            )
        })?;

        // Read password *without echo*
        // Note: rpassword returns String (UTF-8 only), not zeroized
        let passphrase = rpassword::read_password().map_err(|e| {
            SaltyboxError::with_kind_and_source(
                ErrorCategory::Internal,
                ErrorKind::PassphraseUnavailable,
                format!("failure reading passphrase: {}", e),
                e,
            )
        })?;

        Ok(Zeroizing::new(passphrase.into_bytes()))
    }
}

/// Wraps another PassphraseReader and caches the result
///
/// Provides "at most once" semantics - the upstream reader is called
/// only on the first invocation, and subsequent calls return the cached value.
/// The cached passphrase is wrapped in `Zeroizing` and will be securely wiped
/// when this reader is dropped.
pub struct CachingPassphraseReader {
    upstream: Box<dyn PassphraseReader>,
    cached: Option<Zeroizing<Vec<u8>>>,
}

impl CachingPassphraseReader {
    pub fn new(upstream: Box<dyn PassphraseReader>) -> Self {
        Self {
            upstream,
            cached: None,
        }
    }
}

impl PassphraseReader for CachingPassphraseReader {
    fn read_passphrase(&mut self) -> Result<Zeroizing<Vec<u8>>> {
        if self.cached.is_none() {
            let passphrase = self.upstream.read_passphrase()?;
            self.cached = Some(passphrase);
        }
        let inner: &Vec<u8> = self.cached.as_ref().unwrap();
        Ok(Zeroizing::new(inner.clone()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::{ErrorCategory, ErrorKind, SaltyboxError};

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
        let mut reader = TerminalPassphraseReader::new();
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

    #[test]
    fn test_caching_reader() {
        // Track how many times upstream is called
        use std::cell::RefCell;
        use std::rc::Rc;

        struct CountingReader {
            passphrase: Vec<u8>,
            call_count: Rc<RefCell<usize>>,
        }

        impl PassphraseReader for CountingReader {
            fn read_passphrase(&mut self) -> Result<Zeroizing<Vec<u8>>> {
                *self.call_count.borrow_mut() += 1;
                Ok(Zeroizing::new(self.passphrase.clone()))
            }
        }

        let call_count = Rc::new(RefCell::new(0));
        let upstream = CountingReader {
            passphrase: b"cached_pass".to_vec(),
            call_count: call_count.clone(),
        };

        let mut caching = CachingPassphraseReader::new(Box::new(upstream));

        // First call should invoke upstream
        assert_eq!(&*caching.read_passphrase().unwrap(), b"cached_pass");
        assert_eq!(*call_count.borrow(), 1);

        // Second call should return cached value without calling upstream
        assert_eq!(&*caching.read_passphrase().unwrap(), b"cached_pass");
        assert_eq!(*call_count.borrow(), 1);

        // Third call should also use cache
        assert_eq!(&*caching.read_passphrase().unwrap(), b"cached_pass");
        assert_eq!(*call_count.borrow(), 1);
    }

    #[test]
    fn test_caching_reader_with_error() {
        // Reader that always fails
        struct FailingReader;

        impl PassphraseReader for FailingReader {
            fn read_passphrase(&mut self) -> Result<Zeroizing<Vec<u8>>> {
                Err(SaltyboxError::with_kind(
                    ErrorCategory::Internal,
                    ErrorKind::PassphraseUnavailable,
                    "simulated error",
                ))
            }
        }

        let mut caching = CachingPassphraseReader::new(Box::new(FailingReader));

        // First call should propagate error
        assert!(caching.read_passphrase().is_err());

        // Error should not be cached - subsequent call should try again
        assert!(caching.read_passphrase().is_err());
    }
}
