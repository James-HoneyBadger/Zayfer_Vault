use aes_gcm::{
    aead::{Aead, KeyInit, OsRng},
    Aes256Gcm, Nonce,
};
use rand::RngCore;

use crate::error::{HbError, HbResult};

/// Nonce size for AES-256-GCM (96 bits / 12 bytes).
pub const AES_GCM_NONCE_SIZE: usize = 12;
/// Key size for AES-256 (256 bits / 32 bytes).
pub const AES_256_KEY_SIZE: usize = 32;
/// Authentication tag size (128 bits / 16 bytes).
pub const AES_GCM_TAG_SIZE: usize = 16;

/// Encrypt plaintext with AES-256-GCM.
///
/// Returns `(nonce, ciphertext_with_tag)`.
/// The nonce is randomly generated using the OS CSPRNG.
pub fn encrypt(key: &[u8], plaintext: &[u8], aad: &[u8]) -> HbResult<(Vec<u8>, Vec<u8>)> {
    if key.len() != AES_256_KEY_SIZE {
        return Err(HbError::AesGcm(format!(
            "Key must be {AES_256_KEY_SIZE} bytes, got {}",
            key.len()
        )));
    }

    let cipher = Aes256Gcm::new_from_slice(key)
        .map_err(|e| HbError::AesGcm(format!("Invalid key: {e}")))?;

    let mut nonce_bytes = [0u8; AES_GCM_NONCE_SIZE];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let payload = aes_gcm::aead::Payload {
        msg: plaintext,
        aad,
    };

    let ciphertext = cipher
        .encrypt(nonce, payload)
        .map_err(|e| HbError::AesGcm(format!("Encryption failed: {e}")))?;

    Ok((nonce_bytes.to_vec(), ciphertext))
}

/// Decrypt ciphertext with AES-256-GCM.
///
/// # Arguments
/// * `key` — 32-byte key
/// * `nonce` — 12-byte nonce
/// * `ciphertext` — ciphertext with appended authentication tag
/// * `aad` — additional authenticated data (must match what was used during encryption)
pub fn decrypt(key: &[u8], nonce: &[u8], ciphertext: &[u8], aad: &[u8]) -> HbResult<Vec<u8>> {
    if key.len() != AES_256_KEY_SIZE {
        return Err(HbError::AesGcm(format!(
            "Key must be {AES_256_KEY_SIZE} bytes, got {}",
            key.len()
        )));
    }
    if nonce.len() != AES_GCM_NONCE_SIZE {
        return Err(HbError::AesGcm(format!(
            "Nonce must be {AES_GCM_NONCE_SIZE} bytes, got {}",
            nonce.len()
        )));
    }

    let cipher = Aes256Gcm::new_from_slice(key)
        .map_err(|e| HbError::AesGcm(format!("Invalid key: {e}")))?;

    let nonce = Nonce::from_slice(nonce);
    let payload = aes_gcm::aead::Payload {
        msg: ciphertext,
        aad,
    };

    cipher
        .decrypt(nonce, payload)
        .map_err(|_| HbError::AuthenticationFailed)
}

/// Encrypt with a freshly generated nonce, using an incrementing counter.
/// Useful for streaming encryption of chunks.
pub fn encrypt_chunk(
    key: &[u8],
    base_nonce: &[u8; AES_GCM_NONCE_SIZE],
    chunk_index: u64,
    chunk: &[u8],
    aad: &[u8],
) -> HbResult<Vec<u8>> {
    let cipher = Aes256Gcm::new_from_slice(key)
        .map_err(|e| HbError::AesGcm(format!("Invalid key: {e}")))?;

    let mut nonce_bytes = *base_nonce;
    // XOR the last 8 bytes of the nonce with the chunk index
    let idx_bytes = chunk_index.to_le_bytes();
    for i in 0..8 {
        nonce_bytes[4 + i] ^= idx_bytes[i];
    }
    let nonce = Nonce::from_slice(&nonce_bytes);

    // Include chunk index in AAD to prevent reordering
    let mut full_aad = aad.to_vec();
    full_aad.extend_from_slice(&chunk_index.to_le_bytes());

    let payload = aes_gcm::aead::Payload {
        msg: chunk,
        aad: &full_aad,
    };

    cipher
        .encrypt(nonce, payload)
        .map_err(|e| HbError::AesGcm(format!("Chunk encryption failed: {e}")))
}

/// Decrypt a single chunk from a stream.
pub fn decrypt_chunk(
    key: &[u8],
    base_nonce: &[u8; AES_GCM_NONCE_SIZE],
    chunk_index: u64,
    ciphertext: &[u8],
    aad: &[u8],
) -> HbResult<Vec<u8>> {
    let cipher = Aes256Gcm::new_from_slice(key)
        .map_err(|e| HbError::AesGcm(format!("Invalid key: {e}")))?;

    let mut nonce_bytes = *base_nonce;
    let idx_bytes = chunk_index.to_le_bytes();
    for i in 0..8 {
        nonce_bytes[4 + i] ^= idx_bytes[i];
    }
    let nonce = Nonce::from_slice(&nonce_bytes);

    let mut full_aad = aad.to_vec();
    full_aad.extend_from_slice(&chunk_index.to_le_bytes());

    let payload = aes_gcm::aead::Payload {
        msg: ciphertext,
        aad: &full_aad,
    };

    cipher
        .decrypt(nonce, payload)
        .map_err(|_| HbError::AuthenticationFailed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let mut key = [0u8; 32];
        OsRng.fill_bytes(&mut key);
        let plaintext = b"Hello, HB_Zayfer! This is AES-256-GCM.";
        let aad = b"additional data";

        let (nonce, ciphertext) = encrypt(&key, plaintext, aad).unwrap();
        let decrypted = decrypt(&key, &nonce, &ciphertext, aad).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_wrong_key_fails() {
        let mut key = [0u8; 32];
        OsRng.fill_bytes(&mut key);
        let (nonce, ciphertext) = encrypt(&key, b"secret", b"").unwrap();

        let mut wrong_key = [0u8; 32];
        OsRng.fill_bytes(&mut wrong_key);
        let result = decrypt(&wrong_key, &nonce, &ciphertext, b"");
        assert!(result.is_err());
    }

    #[test]
    fn test_wrong_aad_fails() {
        let mut key = [0u8; 32];
        OsRng.fill_bytes(&mut key);
        let (nonce, ciphertext) = encrypt(&key, b"secret", b"correct aad").unwrap();

        let result = decrypt(&key, &nonce, &ciphertext, b"wrong aad");
        assert!(result.is_err());
    }

    #[test]
    fn test_chunk_encrypt_decrypt() {
        let mut key = [0u8; 32];
        OsRng.fill_bytes(&mut key);
        let mut base_nonce = [0u8; 12];
        OsRng.fill_bytes(&mut base_nonce);
        let aad = b"stream";

        for i in 0..5u64 {
            let chunk = format!("chunk data {i}");
            let ct = encrypt_chunk(&key, &base_nonce, i, chunk.as_bytes(), aad).unwrap();
            let pt = decrypt_chunk(&key, &base_nonce, i, &ct, aad).unwrap();
            assert_eq!(pt, chunk.as_bytes());
        }
    }
}
