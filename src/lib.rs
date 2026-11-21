//! Saltybox - Passphrase-based file encryption

#![cfg_attr(not(target_os = "macos"), forbid(unsafe_code))]
// macOS has one audited FFI call to read the target of an open symlink.
#![cfg_attr(target_os = "macos", deny(unsafe_code))]

pub mod error;
pub mod file_ops;
pub mod format;
pub mod format_v2;
pub mod passphrase;
pub mod secretcrypt_v1;
pub mod varmor;

pub use error::{ErrorCategory, ErrorKind, Result, SaltyboxError};
