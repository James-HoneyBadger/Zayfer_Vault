use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Nonce,
};
use rand::RngCore;
use rand_core::OsRng;

use crate::error::{HbError, HbResult};

/// Nonce size for ChaCha20-Poly1305 (96 bits / 12 bytes).
pub const CHACHA20_NONCE_SIZE: usize = 12;
/// Key size for ChaCha20-Poly1305 (256 bits / 32 bytes).
pub const CHACHA20_KEY_SIZE: usize = 32;
/// Authentication tag size (128 bits / 16 bytes).
pub const CHACHA20_TAG_SIZE: usize = 16;

/// Encrypt plaintext with ChaCha20-Poly1305.
///
/// Returns `(nonce, ciphertext_with_tag)`.
pub fn encrypt(key: &[u8], plaintext: &[u8], aad: &[u8]) -> HbResult<(Vec<u8>, Vec<u8>)> {
    if key.len() != CHACHA20_KEY_SIZE {
        return Err(HbError::ChaCha20(format!(
            "Key must be {CHACHA20_KEY_SIZE} bytes, got {}",
            key.len()
        )));
    }

    let cipher = ChaCha20Poly1305::new_from_slice(key)
        .map_err(|e| HbError::ChaCha20(format!("Invalid key: {e}")))?;

    let mut nonce_bytes = [0u8; CHACHA20_NONCE_SIZE];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let payload = chacha20poly1305::aead::Payload {
        msg: plaintext,
        aad,
    };

    let ciphertext = cipher
        .encrypt(nonce, payload)
        .map_err(|e| HbError::ChaCha20(format!("Encryption failed: {e}")))?;

    Ok((nonce_bytes.to_vec(), ciphertext))
}

/// Decrypt ciphertext with ChaCha20-Poly1305.
pub fn decrypt(key: &[u8], nonce: &[u8], ciphertext: &[u8], aad: &[u8]) -> HbResult<Vec<u8>> {
    if key.len() != CHACHA20_KEY_SIZE {
        return Err(HbError::ChaCha20(format!(
            "Key must be {CHACHA20_KEY_SIZE} bytes, got {}",
            key.len()
        )));
    }
    if nonce.len() != CHACHA20_NONCE_SIZE {
        return Err(HbError::ChaCha20(format!(
            "Nonce must be {CHACHA20_NONCE_SIZE} bytes, got {}",
            nonce.len()
        )));
    }

    let cipher = ChaCha20Poly1305::new_from_slice(key)
        .map_err(|e| HbError::ChaCha20(format!("Invalid key: {e}")))?;

    let nonce = Nonce::from_slice(nonce);
    let payload = chacha20poly1305::aead::Payload {
        msg: ciphertext,
        aad,
    };

    cipher
        .decrypt(nonce, payload)
        .map_err(|_| HbError::AuthenticationFailed)
}

/// Encrypt a chunk for streaming.
pub fn encrypt_chunk(
    key: &[u8],
    base_nonce: &[u8; CHACHA20_NONCE_SIZE],
    chunk_index: u64,
    chunk: &[u8],
    aad: &[u8],
) -> HbResult<Vec<u8>> {
    let cipher = ChaCha20Poly1305::new_from_slice(key)
        .map_err(|e| HbError::ChaCha20(format!("Invalid key: {e}")))?;

    let mut nonce_bytes = *base_nonce;
    let idx_bytes = chunk_index.to_le_bytes();
    for i in 0..8 {
        nonce_bytes[4 + i] ^= idx_bytes[i];
    }
    let nonce = Nonce::from_slice(&nonce_bytes);

    let mut full_aad = aad.to_vec();
    full_aad.extend_from_slice(&chunk_index.to_le_bytes());

    let payload = chacha20poly1305::aead::Payload {
        msg: chunk,
        aad: &full_aad,
    };

    cipher
        .encrypt(nonce, payload)
        .map_err(|e| HbError::ChaCha20(format!("Chunk encryption failed: {e}")))
}

/// Decrypt a single chunk from a stream.
pub fn decrypt_chunk(
    key: &[u8],
    base_nonce: &[u8; CHACHA20_NONCE_SIZE],
    chunk_index: u64,
    ciphertext: &[u8],
    aad: &[u8],
) -> HbResult<Vec<u8>> {
    let cipher = ChaCha20Poly1305::new_from_slice(key)
        .map_err(|e| HbError::ChaCha20(format!("Invalid key: {e}")))?;

    let mut nonce_bytes = *base_nonce;
    let idx_bytes = chunk_index.to_le_bytes();
    for i in 0..8 {
        nonce_bytes[4 + i] ^= idx_bytes[i];
    }
    let nonce = Nonce::from_slice(&nonce_bytes);

    let mut full_aad = aad.to_vec();
    full_aad.extend_from_slice(&chunk_index.to_le_bytes());

    let payload = chacha20poly1305::aead::Payload {
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
        let plaintext = b"Hello, HB_Zayfer! ChaCha20-Poly1305 test.";
        let aad = b"test aad";

        let (nonce, ciphertext) = encrypt(&key, plaintext, aad).unwrap();
        let decrypted = decrypt(&key, &nonce, &ciphertext, aad).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_tampered_ciphertext_fails() {
        let mut key = [0u8; 32];
        OsRng.fill_bytes(&mut key);
        let (nonce, mut ciphertext) = encrypt(&key, b"secret data", b"").unwrap();

        if let Some(byte) = ciphertext.get_mut(0) {
            *byte ^= 0xff;
        }
        let result = decrypt(&key, &nonce, &ciphertext, b"");
        assert!(result.is_err());
    }

    #[test]
    fn test_chunk_streaming() {
        let mut key = [0u8; 32];
        OsRng.fill_bytes(&mut key);
        let mut base_nonce = [0u8; 12];
        OsRng.fill_bytes(&mut base_nonce);

        for i in 0..10u64 {
            let data = format!("chunk {i} data");
            let ct = encrypt_chunk(&key, &base_nonce, i, data.as_bytes(), b"stream").unwrap();
            let pt = decrypt_chunk(&key, &base_nonce, i, &ct, b"stream").unwrap();
            assert_eq!(pt, data.as_bytes());
        }
    }
}
