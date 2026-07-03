//! Saltybox - Passphrase-based file encryption using NaCl secretbox

#![forbid(unsafe_code)]

pub mod error;
pub mod file_ops;
pub mod format;
pub mod passphrase;
pub mod secretcrypt_v1;
pub mod varmor;

pub use error::{ErrorCategory, ErrorKind, Result, SaltyboxError};
