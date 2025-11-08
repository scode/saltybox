//! Saltybox - Passphrase-based file encryption using NaCl secretbox

#![forbid(unsafe_code)]

pub mod cli;
pub mod file_ops;
pub mod passphrase;
pub mod secretcrypt;
pub mod varmor;
