use std::path::PathBuf;

use clap::{ArgAction, Parser, Subcommand};

use saltybox_rs::{commands, preader};

#[derive(Parser, Debug)]
#[command(name = "saltybox", version, about = "an encryption tool", disable_version_flag = true)]
struct Cli {
    /// Read passphrase from stdin instead of from terminal
    #[arg(long = "passphrase-stdin", action = ArgAction::SetTrue, global = true)]
    passphrase_stdin: bool,

    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Encrypt a file
    Encrypt {
        /// Path to the file whose contents is to be encrypted
        #[arg(short = 'i', long = "input")]
        input: PathBuf,
        /// Path to the file to write the encrypted text to
        #[arg(short = 'o', long = "output")]
        output: PathBuf,
    },
    /// Decrypt a file
    Decrypt {
        /// Path to the file whose contents is to be decrypted
        #[arg(short = 'i', long = "input")]
        input: PathBuf,
        /// Path to the file to write the unencrypted text to
        #[arg(short = 'o', long = "output")]
        output: PathBuf,
    },
    /// Update an encrypted file with new content
    Update {
        /// Path to the file whose contents is to be encrypted
        #[arg(short = 'i', long = "input")]
        input: PathBuf,
        /// Path to the existing saltybox file to replace with encrypted text
        #[arg(short = 'o', long = "output")]
        output: PathBuf,
    },
}

fn main() {
    let cli = Cli::parse();

    let mut get_reader = || -> Box<dyn preader::PassphraseReader> {
        if cli.passphrase_stdin {
            Box::new(preader::ReaderPassphraseReader::new(std::io::stdin()))
        } else {
            Box::new(preader::TerminalPassphraseReader::new())
        }
    };

    let result = match cli.command {
        Some(Commands::Encrypt { input, output }) => {
            commands::encrypt(&input, &output, get_reader())
        }
        Some(Commands::Decrypt { input, output }) => {
            commands::decrypt(&input, &output, get_reader())
        }
        Some(Commands::Update { input, output }) => {
            commands::update(&input, &output, get_reader())
        }
        None => Err(anyhow::anyhow!("command is required; use --help to see list of commands")),
    };

    if let Err(err) = result {
        eprintln!("{}", err);
        std::process::exit(1);
    }
}

