mod shamir;
mod wrapper;

use std::{path::PathBuf, io::{Write, stdout}};

use anyhow::{Ok, Result};
use clap::Parser;
use std::fs;

use crate::wrapper::from_shares;

/// A program that helps you encrypt and decrypt files using Shamir's Secret Sharing
#[derive(Parser, Debug)]
#[command(author, version)]
struct Cli {
    #[command(subcommand)]
    command: SubCommand,
}

#[derive(Parser, Debug)]
enum SubCommand {
    /// Encrypt a file
    Encrypt(EncryptCommand),
    /// Decrypt a file
    Decrypt(DecryptCommand),
}

#[derive(Parser, Debug)]
struct EncryptCommand {
    /// The number of shares to create
    #[clap(short, long, default_value = "5")]
    shares: u8,

    /// The threshold of shares needed to decrypt
    #[clap(short, long, default_value = "3")]
    threshold: u8,

    /// The output folder
    #[clap(short, long)]
    output: PathBuf,

    /// The file to encrypt
    file: PathBuf,
}

#[derive(Parser, Debug)]
struct DecryptCommand {
    /// The output file
    #[clap(short, long)]
    output: Option<PathBuf>,

    /// The files to decrypt
    files: Vec<PathBuf>,
}

fn main() -> Result<()> {
    let args = Cli::parse();

    match args.command {
        SubCommand::Encrypt(arguments) => handle_encrypt(arguments)?,
        SubCommand::Decrypt(arguments) => handle_decrypt(arguments)?,
    };

    Ok(())
}

fn handle_encrypt(arguments: EncryptCommand) -> Result<()> {
    // Get reference to output folder, and check if it exists and is a folder, don't create it
    if !arguments.output.exists() {
        return Err(anyhow::anyhow!(
            "Output folder \"{}\" does not exist",
            arguments.output.display()
        ));
    }

    if !arguments.output.is_dir() {
        return Err(anyhow::anyhow!(
            "Output folder \"{}\" is not a folder",
            arguments.output.display()
        ));
    }

    // Get reference to file, and check if it exists and is a file
    if !arguments.file.exists() {
        return Err(anyhow::anyhow!(
            "File \"{}\" does not exist",
            arguments.file.display()
        ));
    }

    if !arguments.file.is_file() {
        return Err(anyhow::anyhow!(
            "File \"{}\" is not a file",
            arguments.file.display()
        ));
    }

    // Read file into vec
    let file_data = fs::read(arguments.file)?;
    let shares = wrapper::to_shares(file_data, arguments.threshold, arguments.shares)?;

    // Write shares to output folder
    for (i, share) in shares.iter().enumerate() {
        let share_path = arguments.output.join(format!("share{}.ss", i));
        fs::write(share_path, share)?;
    }

    println!("Done");

    Ok(())
}

fn handle_decrypt(arguments: DecryptCommand) -> Result<()> {
    if let Some(output) = arguments.output.to_owned() {
        // Check if output file is creatable, (as in, it is in a folder that exists)
        if !output.parent().unwrap().exists() {
            return Err(anyhow::anyhow!(
                "Cannot create output file \"{}\"",
                output.display()
            ));
        }
    }

    // Check if input files exist and are files
    for file in arguments.files.iter() {
        if !file.exists() {
            return Err(anyhow::anyhow!(
                "File \"{}\" does not exist",
                file.display()
            ));
        }

        if !file.is_file() {
            return Err(anyhow::anyhow!("File \"{}\" is not a file", file.display()));
        }
    }

    // Read shares
    let mut shares: Vec<Vec<u8>> = Vec::new();
    for file in arguments.files.iter() {
        shares.push(fs::read(file)?);
    }

    // Decrypt shares
    let decrypted = from_shares(shares)?;

    // Write decrypted data to output file
    if let Some(output) = arguments.output.to_owned() {
        fs::write(output, decrypted)?;

        println!("Done");
    } else {
        // Write to stdout
        stdout().write_all(&decrypted)?;
    }

    Ok(())
}
