use sha3::{Digest, Sha3_256};

mod shamir;
use shamir::{SecretData, ShamirError};

use clap::Parser;

/// Simple program to greet a person
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Name of the person to greet
    #[arg(short, long)]
    input: String,

    /// Number of times to greet
    #[arg(short, long, default_value_t = 1)]
    count: u8,
}

fn create_unverifyable_shares(input: Vec<u8>, n: u8, k: u8) -> Result<Vec<Vec<u8>>, ShamirError> {
    let secret_data = SecretData::with_secret(input, n);
    let mut shares: Vec<Vec<u8>> = Vec::new();
    for i in 1..=k {
        let share = secret_data.get_share(i)?;
        shares.push(share);
    }
    Ok(shares)
}

fn create_verifyable_shares(input: Vec<u8>, n: u8, k: u8) -> Result<Vec<Vec<u8>>, ShamirError> {
    let unverifyable_shares = create_unverifyable_shares(input.clone(), n, k)?;

    let input_sha3: [u8; 32] = Sha3_256::digest(&input).into();
    let shares_for_verifying = create_unverifyable_shares(input_sha3.into(), n, k)?;

    let mut shares: Vec<Vec<u8>> = Vec::new();
    for i in 0..k as usize {
        let mut share: Vec<u8> = Vec::new();
        share.extend_from_slice(&shares_for_verifying[i]);
        share.extend_from_slice(&unverifyable_shares[i]);
        shares.push(share);
    }

    Ok(shares)
}

fn retrieve_from_shares(input: Vec<Vec<u8>>) -> Option<Vec<u8>> {
    let shares_for_verifying: Vec<Vec<u8>> = input.iter().map(|share| share[0..33].to_vec()).collect();
    let unverifyable_shares: Vec<Vec<u8>> = input.iter().map(|share| share[33..].to_vec()).collect();

    let input_sha3: Vec<u8> = SecretData::recover_secret(shares_for_verifying)?.into();
    let output: Vec<u8> = SecretData::recover_secret(unverifyable_shares)?.into();

    let output_sha3: [u8; 32] = Sha3_256::digest(&output).into();
    let output_sha3_vec: Vec<u8> = output_sha3.into();

    if input_sha3 == output_sha3_vec {
        Some(output)
    } else {
        None
    }
}



fn main() {
    println!("Hello, world!");

    let shares = create_verifyable_shares("Test Data".as_bytes().into(), 3, 5).unwrap();


    // log all
    println!("share1: {:x?}", shares[0]);
    println!("share2: {:x?}", shares[1]);
    println!("share3: {:x?}", shares[2]);
    println!("share4: {:x?}", shares[3]);
    println!("share5: {:x?}", shares[4]);


    // Delete share 1 and 3
    let mut shares2 = shares.clone();
    shares2.remove(1);
    shares2.remove(3);
    shares2.remove(0);


    let retrieved = retrieve_from_shares(shares2).unwrap();
    println!("retrieved: {:?}", retrieved);
}