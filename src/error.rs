use std::error::Error as StdError;

use thiserror::Error;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ErrorCategory {
    /// Any failure that cannot be confidently attributed to any other error
    /// caterogy in this enum.
    ///
    /// In particular this means that use of Internal is never a guarantee
    /// the error is not, for example due to a user error - merely that it
    /// cannot be confidently determined by the code.
    Internal,

    /// The user provided invalid input or performed an action that is
    /// unsupported or impossible to complete.
    User,
}

/// Fine-grained condition flags for consumers that want to branch on error kinds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ErrorKind {
    /// The armored representation is malformed (prefix, encoding, or unsupported version).
    ArmoringInvalid,
    /// Base64 decoding of the armored payload failed.
    ArmoringDecode,
    /// Input claimed to be saltybox but used a future/unsupported version.
    ArmoringFromFuture,
    /// Plaintext/ciphertext length fields or binary layout are invalid.
    BinaryFormat,
    /// Input data ended before the expected component could be read.
    TruncatedInput,
    /// Additional bytes were present after the sealed payload.
    TrailingData,
    /// Authentication failed due to an incorrect passphrase or tampering
    /// or corruption.
    AuthenticationFailed,
    /// Passphrase could not be obtained from the configured reader.
    PassphraseUnavailable,
    /// Low-level scrypt key derivation failed.
    ScryptFailure,
    /// NaCl secretbox (XSalsa20Poly1305) failed to seal or open data.
    SecretboxFailure,
    /// Unexpected state reached within saltybox logic.
    InternalInvariant,
    /// Interaction with the filesystem, stdin/stdout, or other I/O failed.
    Io,
}

#[derive(Debug, Error)]
#[error("{msg}")]
pub struct SaltyboxError {
    /// Broad error category, always provided.
    pub category: ErrorCategory,
    /// Optional specific condition tag for consumers that need to
    /// branch their behavior. Any code consuming errors MUST handle
    /// the absence of a defined kind.
    pub kind: Option<ErrorKind>,
    #[source]
    source: Option<Box<dyn StdError + Send + Sync + 'static>>,
    msg: String,
}

impl SaltyboxError {
    /// Creates a new error with a required category and display message.
    pub fn new(category: ErrorCategory, msg: impl Into<String>) -> Self {
        Self {
            category,
            kind: None,
            source: None,
            msg: msg.into(),
        }
    }

    /// Creates a new error that also tags the failure with a kind.
    pub fn with_kind(category: ErrorCategory, kind: ErrorKind, msg: impl Into<String>) -> Self {
        Self {
            category,
            kind: Some(kind),
            source: None,
            msg: msg.into(),
        }
    }

    /// Creates a new error that retains the originating source error.
    pub fn with_source(
        category: ErrorCategory,
        msg: impl Into<String>,
        source: impl StdError + Send + Sync + 'static,
    ) -> Self {
        Self {
            category,
            kind: None,
            source: Some(Box::new(source)),
            msg: msg.into(),
        }
    }

    /// Creates a new error that carries both a kind tag and the originating source error.
    pub fn with_kind_and_source(
        category: ErrorCategory,
        kind: ErrorKind,
        msg: impl Into<String>,
        source: impl StdError + Send + Sync + 'static,
    ) -> Self {
        Self {
            category,
            kind: Some(kind),
            source: Some(Box::new(source)),
            msg: msg.into(),
        }
    }

    /// The user-facing message carried by the error.
    pub fn message(&self) -> &str {
        &self.msg
    }

    /// Returns the preserved source error if present.
    pub fn source_error(&self) -> Option<&(dyn StdError + Send + Sync + 'static)> {
        self.source.as_deref()
    }

    /// Wraps the current error with a higher-level message while preserving the original as source.
    pub fn with_context(self, msg: impl Into<String>) -> Self {
        let category = self.category;
        let kind = self.kind;
        Self {
            category,
            kind,
            source: Some(Box::new(self)),
            msg: msg.into(),
        }
    }
}

/// Convenience alias.
pub type Result<T> = std::result::Result<T, SaltyboxError>;
