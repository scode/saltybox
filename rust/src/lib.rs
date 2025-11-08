//! Saltybox - Passphrase-based file encryption using NaCl secretbox
//!
//! This is a Rust implementation of saltybox, maintaining exact compatibility
//! with the original Go implementation's on-disk format.
//!
//! # Architecture
//!
//! - `crypto`: Core encryption/decryption using scrypt + XSalsa20Poly1305
//! - `armor`: Base64url encoding/decoding with version prefix
//! - `passphrase`: Terminal passphrase reading and management
//! - `cli`: Command-line interface (feature-gated)

#![forbid(unsafe_code)]
#![warn(missing_docs, rust_2018_idioms)]

pub mod crypto;
pub mod armor;
pub mod passphrase;

#[cfg(feature = "cli")]
pub mod cli;

// Re-export main types for convenience
pub use crypto::{encrypt, decrypt};
pub use armor::{wrap, unwrap};
