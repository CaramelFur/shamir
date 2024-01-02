use aes_gcm::{
    aead::{Aead, AeadCore, KeyInit},
    Aes256Gcm, Key,
};
use anyhow::Result;
use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_256};

mod shamir;
use shamir::SecretData;

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

#[derive(Debug, Serialize, Deserialize)]
struct ShareInfo {
    length: usize,
    shares: u8,
    hash: [u8; 32],
    key: [u8; 32],
    nonce: [u8; 12],
}

#[derive(Debug, Serialize, Deserialize)]
struct Share {
    info: Vec<u8>,
    data: Vec<u8>,
}

fn create_unverifyable_shares(input: Vec<u8>, threshold: u8, count: u8) -> Result<Vec<Vec<u8>>> {
    let secret_data = SecretData::with_secret(input, threshold);
    let mut shares: Vec<Vec<u8>> = Vec::new();
    for i in 1..=count {
        let share = secret_data.get_share(i)?;
        shares.push(share);
    }
    Ok(shares)
}

fn create_verifyable_shares(input: Vec<u8>, threshold: u8, count: u8) -> Result<Vec<Vec<u8>>> {
    let mut rng = rand::thread_rng();

    let key = Aes256Gcm::generate_key(&mut rng);
    let nonce = Aes256Gcm::generate_nonce(&mut rng);

    let info = ShareInfo {
        length: input.len(),
        shares: count,
        hash: Sha3_256::digest(&input).into(),
        key: key.into(),
        nonce: nonce.into(),
    };

    let info_serialized = bincode::serialize(&info).unwrap();

    let unverifyable_shares = create_unverifyable_shares(info_serialized, threshold, count)?;

    // Encrypt input with aes-gcm crate
    let cipher = Aes256Gcm::new(&key);
    let ciphertext = cipher
        .encrypt(&nonce, input.as_slice())
        .map_err(|_| anyhow::anyhow!("Encryption failed"))?;

    let mut shares: Vec<Vec<u8>> = Vec::new();
    for i in 0..count as usize {
        let share = Share {
            info: unverifyable_shares[i].to_vec(),
            data: ciphertext.to_vec(),
        };

        let share_serialized = bincode::serialize(&share).unwrap();
        shares.push(share_serialized);
    }

    Ok(shares)
}

fn retrieve_from_shares(input: Vec<Vec<u8>>) -> Result<Vec<u8>> {
    // Return if no shares are given
    if input.len() == 0 {
        return Ok(vec![]);
    }

    let mut shares: Vec<Share> = Vec::new();
    for share in input {
        let share: Share = bincode::deserialize(&share)?;
        shares.push(share);
    }

    // Check if all shares have the same encrypted data
    let encrypted_data: Vec<u8> = shares[0].data.to_vec();
    for share in shares.iter_mut() {
        if share.data != encrypted_data {
            return Err(anyhow::anyhow!("Shares do not match"));
        }
        share.data.clear(); // Not needed anymore
    }

    // Decrypt share info
    let decrypted = SecretData::recover_secret(
        shares
            .iter()
            .map(|s| s.info.to_vec())
            .collect::<Vec<Vec<u8>>>(),
    )?;

    let info: ShareInfo = bincode::deserialize(&decrypted)?;

    // Decrypt data
    let key = Key::<Aes256Gcm>::from_slice(&info.key);
    let cipher = Aes256Gcm::new(key);
    let plaintext = cipher
        .decrypt(&info.nonce.into(), encrypted_data.as_ref())
        .map_err(|_| anyhow::anyhow!("Decryption failed"))?;

    // Check if hash matches
    let hash: [u8; 32] = Sha3_256::digest(&plaintext).into();
    if info.hash != hash {
        return Err(anyhow::anyhow!("Hashes do not match"));
    }

    Ok(plaintext)
}

fn main() {
    println!("Hello, world!");

    let shares = create_verifyable_shares("Test Data Helloa".as_bytes().into(), 3, 5).unwrap();

    // log all
    println!("share2: {} {:x?}", shares[1].len(), shares[1]);
    println!("share1: {} {:x?}", shares[0].len(), shares[0]);
    println!("share3: {} {:x?}", shares[2].len(), shares[2]);
    println!("share4: {} {:x?}", shares[3].len(), shares[3]);
    println!("share5: {} {:x?}", shares[4].len(), shares[4]);

    // Delete share 1 and 3
    let mut shares2 = shares.clone();
    shares2.remove(1);
    shares2.remove(3);
    shares2.remove(0);

    let retrieved = retrieve_from_shares(shares2).unwrap();
    println!("retrieved: {:?}", retrieved);

    // print as utf8
    println!("retrieved: {}", String::from_utf8(retrieved).unwrap());
}
