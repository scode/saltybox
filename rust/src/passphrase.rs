//! Passphrase reading functionality

use anyhow::Result;

pub trait PassphraseReader {
    /// Read a passphrase
    fn read_passphrase(&mut self) -> Result<String>;
}

pub struct TerminalReader;

impl TerminalReader {
    pub fn new() -> Self {
        Self
    }
}

impl Default for TerminalReader {
    fn default() -> Self {
        Self::new()
    }
}

impl PassphraseReader for TerminalReader {
    fn read_passphrase(&mut self) -> Result<String> {
        // TODO: Step 4 - Passphrase Reading
        todo!("terminal passphrase reading not yet implemented")
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn test_placeholder() {
        // Placeholder test.
    }
}
