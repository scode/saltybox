//! Passphrase reading functionality

use crate::error::{ErrorCategory, ErrorKind, Result, SaltyboxError};
use std::io::{self, IsTerminal, Read, Write};

/// Trait for reading passphrases from various sources
pub trait PassphraseReader {
    /// Read a passphrase
    fn read_passphrase(&mut self) -> Result<String>;
}

/// Returns a fixed passphrase (for testing)
pub struct ConstantPassphraseReader {
    passphrase: String,
}

impl ConstantPassphraseReader {
    pub fn new(passphrase: String) -> Self {
        Self { passphrase }
    }
}

impl PassphraseReader for ConstantPassphraseReader {
    fn read_passphrase(&mut self) -> Result<String> {
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
    fn read_passphrase(&mut self) -> Result<String> {
        let mut data = Vec::new();
        self.reader.read_to_end(&mut data).map_err(|e| {
            SaltyboxError::with_kind_and_source(
                ErrorCategory::Internal,
                ErrorKind::Io,
                format!("error reading passphrase: {}", e),
                e,
            )
        })?;
        String::from_utf8(data).map_err(|e| {
            SaltyboxError::with_kind_and_source(
                ErrorCategory::User,
                ErrorKind::PassphraseUnavailable,
                format!("passphrase is not valid UTF-8: {}", e),
                e,
            )
        })
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
    fn read_passphrase(&mut self) -> Result<String> {
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
        let passphrase = rpassword::read_password().map_err(|e| {
            SaltyboxError::with_kind_and_source(
                ErrorCategory::Internal,
                ErrorKind::PassphraseUnavailable,
                format!("failure reading passphrase: {}", e),
                e,
            )
        })?;

        Ok(passphrase)
    }
}

/// Wraps another PassphraseReader and caches the result
///
/// Provides "at most once" semantics - the upstream reader is called
/// only on the first invocation, and subsequent calls return the cached value.
pub struct CachingPassphraseReader {
    upstream: Box<dyn PassphraseReader>,
    cached: Option<String>,
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
    fn read_passphrase(&mut self) -> Result<String> {
        if self.cached.is_none() {
            let passphrase = self.upstream.read_passphrase()?;
            self.cached = Some(passphrase);
        }
        Ok(self.cached.as_ref().unwrap().clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::{ErrorCategory, ErrorKind, SaltyboxError};

    #[test]
    fn test_constant_reader() {
        let mut reader = ConstantPassphraseReader::new("test123".to_string());
        assert_eq!(reader.read_passphrase().unwrap(), "test123");
        assert_eq!(reader.read_passphrase().unwrap(), "test123");
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
        println!("You entered: {}", passphrase);
        assert!(!passphrase.is_empty(), "Expected non-empty passphrase");
    }

    #[test]
    fn test_reader_passphrase_reader() {
        let data = b"mypassword";
        let mut reader = ReaderPassphraseReader::new(Box::new(&data[..]));
        assert_eq!(reader.read_passphrase().unwrap(), "mypassword");
    }

    #[test]
    fn test_reader_passphrase_reader_empty() {
        let data = b"";
        let mut reader = ReaderPassphraseReader::new(Box::new(&data[..]));
        assert_eq!(reader.read_passphrase().unwrap(), "");
    }

    #[test]
    fn test_caching_reader() {
        // Track how many times upstream is called
        use std::cell::RefCell;
        use std::rc::Rc;

        struct CountingReader {
            passphrase: String,
            call_count: Rc<RefCell<usize>>,
        }

        impl PassphraseReader for CountingReader {
            fn read_passphrase(&mut self) -> Result<String> {
                *self.call_count.borrow_mut() += 1;
                Ok(self.passphrase.clone())
            }
        }

        let call_count = Rc::new(RefCell::new(0));
        let upstream = CountingReader {
            passphrase: "cached_pass".to_string(),
            call_count: call_count.clone(),
        };

        let mut caching = CachingPassphraseReader::new(Box::new(upstream));

        // First call should invoke upstream
        assert_eq!(caching.read_passphrase().unwrap(), "cached_pass");
        assert_eq!(*call_count.borrow(), 1);

        // Second call should return cached value without calling upstream
        assert_eq!(caching.read_passphrase().unwrap(), "cached_pass");
        assert_eq!(*call_count.borrow(), 1);

        // Third call should also use cache
        assert_eq!(caching.read_passphrase().unwrap(), "cached_pass");
        assert_eq!(*call_count.borrow(), 1);
    }

    #[test]
    fn test_caching_reader_with_error() {
        // Reader that always fails
        struct FailingReader;

        impl PassphraseReader for FailingReader {
            fn read_passphrase(&mut self) -> Result<String> {
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
