//! Saltybox CLI - Passphrase-based file encryption
//!
//! Command-line interface for encrypting and decrypting files using
//! NaCl secretbox (XSalsa20Poly1305) with scrypt key derivation.

use clap::{Parser, Subcommand};
use std::path::PathBuf;
use std::process;

use saltybox::file_ops;
use saltybox::passphrase::{PassphraseReader, ReaderPassphraseReader, TerminalPassphraseReader};

#[derive(Parser)]
#[command(name = "saltybox")]
#[command(version)]
#[command(about = "Passphrase-based file encryption.", long_about = None)]
struct Cli {
    /// Read passphrase from stdin instead of from terminal
    #[arg(long, global = true)]
    passphrase_stdin: bool,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Encrypt a file
    #[command(alias = "e")]
    Encrypt {
        /// Path to the file whose contents is to be encrypted
        #[arg(short, long, value_name = "FILE")]
        input: PathBuf,

        /// Path to the file to write the encrypted text to
        #[arg(short, long, value_name = "FILE")]
        output: PathBuf,
    },

    /// Decrypt a file
    #[command(alias = "d")]
    Decrypt {
        /// Path to the file whose contents is to be decrypted
        #[arg(short, long, value_name = "FILE")]
        input: PathBuf,

        /// Path to the file to write the unencrypted text to
        #[arg(short, long, value_name = "FILE")]
        output: PathBuf,
    },

    /// Update an encrypted file with new content, while validating
    /// that the passphrase is not accidentally changed.
    #[command(alias = "u")]
    Update {
        /// Path to the file whose contents is to be encrypted
        #[arg(short, long, value_name = "FILE")]
        input: PathBuf,

        /// Path to the existing saltybox file to replace with encrypted text
        #[arg(short, long, value_name = "FILE")]
        output: PathBuf,
    },
}

fn main() {
    let cli = Cli::parse();

    let result = match cli.command {
        Commands::Encrypt { input, output } => {
            let mut reader = get_passphrase_reader(cli.passphrase_stdin);
            file_ops::encrypt_file(&input, &output, &mut *reader)
        }
        Commands::Decrypt { input, output } => {
            let mut reader = get_passphrase_reader(cli.passphrase_stdin);
            file_ops::decrypt_file(&input, &output, &mut *reader)
        }
        Commands::Update { input, output } => {
            let mut reader = get_passphrase_reader(cli.passphrase_stdin);
            file_ops::update_file(&input, &output, &mut *reader)
        }
    };

    if let Err(e) = result {
        eprintln!("Error: {:#}", e);
        process::exit(1);
    }
}

fn get_passphrase_reader(use_stdin: bool) -> Box<dyn PassphraseReader> {
    if use_stdin {
        Box::new(ReaderPassphraseReader::new(Box::new(std::io::stdin())))
    } else {
        Box::new(TerminalPassphraseReader)
    }
}
