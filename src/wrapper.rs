use aes_gcm::{
  aead::{Aead, AeadCore, KeyInit},
  Aes256Gcm, Key,
};
use anyhow::Result;
use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_256};

use crate::shamir::SecretData;

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

fn create_raw_shares(input: Vec<u8>, threshold: u8, count: u8) -> Result<Vec<Vec<u8>>> {
    let secret_data = SecretData::with_secret(input, threshold);
    let mut shares: Vec<Vec<u8>> = Vec::new();
    for i in 1..=count {
        let share = secret_data.get_share(i)?;
        shares.push(share);
    }
    Ok(shares)
}

pub fn to_shares(input: Vec<u8>, threshold: u8, count: u8) -> Result<Vec<Vec<u8>>> {
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

    let unverifyable_shares = create_raw_shares(info_serialized, threshold, count)?;

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

pub fn from_shares(input: Vec<Vec<u8>>) -> Result<Vec<u8>> {
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
