use std::io::{self, Read};

pub trait PassphraseReader {
    fn read_passphrase(&mut self) -> io::Result<String>;
}

impl<T: PassphraseReader + ?Sized> PassphraseReader for Box<T> {
    fn read_passphrase(&mut self) -> io::Result<String> {
        (**self).read_passphrase()
    }
}

pub struct TerminalPassphraseReader;

impl TerminalPassphraseReader {
    pub fn new() -> Self { Self }
}

impl PassphraseReader for TerminalPassphraseReader {
    fn read_passphrase(&mut self) -> io::Result<String> {
        let pass = rpassword::prompt_password("Passphrase (saltybox): ")
            .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("failure reading passphrase: {}", e)))?;
        Ok(pass)
    }
}

pub struct ReaderPassphraseReader<R: Read> {
    reader: R,
}

impl<R: Read> ReaderPassphraseReader<R> {
    pub fn new(reader: R) -> Self { Self { reader } }
}

impl<R: Read> PassphraseReader for ReaderPassphraseReader<R> {
    fn read_passphrase(&mut self) -> io::Result<String> {
        let mut data = String::new();
        self.reader.read_to_string(&mut data)?;
        Ok(data)
    }
}

pub struct ConstantPassphraseReader {
    passphrase: String,
}

impl ConstantPassphraseReader {
    pub fn new(passphrase: String) -> Self { Self { passphrase } }
}

impl PassphraseReader for ConstantPassphraseReader {
    fn read_passphrase(&mut self) -> io::Result<String> {
        Ok(self.passphrase.clone())
    }
}

pub struct CachingPassphraseReader<P: PassphraseReader> {
    upstream: P,
    cached: Option<String>,
}

impl<P: PassphraseReader> CachingPassphraseReader<P> {
    pub fn new(upstream: P) -> Self { Self { upstream, cached: None } }
}

impl<P: PassphraseReader> PassphraseReader for CachingPassphraseReader<P> {
    fn read_passphrase(&mut self) -> io::Result<String> {
        if let Some(cached) = &self.cached { return Ok(cached.clone()); }
        let phrase = self.upstream.read_passphrase()?;
        self.cached = Some(phrase.clone());
        Ok(phrase)
    }
}

