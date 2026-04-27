//! AES-256-GCM authenticated encryption.
//!
//! All real work lives in [`crate::aead`]; this module is a thin
//! cipher-specific facade preserving the historical public API
//! (`encrypt`, `decrypt`, `encrypt_chunk`, `decrypt_chunk`).

use aes_gcm::Aes256Gcm;

use crate::aead as shared;
use crate::error::HbResult;

/// Nonce size for AES-256-GCM (96 bits / 12 bytes).
pub const AES_GCM_NONCE_SIZE: usize = shared::NONCE_SIZE;
/// Key size for AES-256 (256 bits / 32 bytes).
pub const AES_256_KEY_SIZE: usize = shared::KEY_SIZE;
/// Authentication tag size (128 bits / 16 bytes).
pub const AES_GCM_TAG_SIZE: usize = shared::TAG_SIZE;

const KIND: shared::CipherKind = shared::CipherKind::AesGcm;

/// Encrypt plaintext with AES-256-GCM. Returns `(nonce, ciphertext_with_tag)`.
pub fn encrypt(key: &[u8], plaintext: &[u8], aad: &[u8]) -> HbResult<(Vec<u8>, Vec<u8>)> {
    shared::encrypt::<Aes256Gcm>(KIND, key, plaintext, aad)
}

/// Decrypt ciphertext with AES-256-GCM.
pub fn decrypt(key: &[u8], nonce: &[u8], ciphertext: &[u8], aad: &[u8]) -> HbResult<Vec<u8>> {
    shared::decrypt::<Aes256Gcm>(KIND, key, nonce, ciphertext, aad)
}

/// Streaming chunk encrypt with derived per-chunk nonce.
pub fn encrypt_chunk(
    key: &[u8],
    base_nonce: &[u8; AES_GCM_NONCE_SIZE],
    chunk_index: u64,
    chunk: &[u8],
    aad: &[u8],
) -> HbResult<Vec<u8>> {
    shared::encrypt_chunk::<Aes256Gcm>(KIND, key, base_nonce, chunk_index, chunk, aad)
}

/// Streaming chunk decrypt with derived per-chunk nonce.
pub fn decrypt_chunk(
    key: &[u8],
    base_nonce: &[u8; AES_GCM_NONCE_SIZE],
    chunk_index: u64,
    ciphertext: &[u8],
    aad: &[u8],
) -> HbResult<Vec<u8>> {
    shared::decrypt_chunk::<Aes256Gcm>(KIND, key, base_nonce, chunk_index, ciphertext, aad)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::RngCore;
    use rand_core::OsRng;

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
        assert!(decrypt(&wrong_key, &nonce, &ciphertext, b"").is_err());
    }

    #[test]
    fn test_wrong_aad_fails() {
        let mut key = [0u8; 32];
        OsRng.fill_bytes(&mut key);
        let (nonce, ciphertext) = encrypt(&key, b"secret", b"correct aad").unwrap();
        assert!(decrypt(&key, &nonce, &ciphertext, b"wrong aad").is_err());
    }

    #[test]
    fn test_chunk_encrypt_decrypt() {
        let mut key = [0u8; 32];
        OsRng.fill_bytes(&mut key);
        let mut base_nonce = [0u8; 12];
        OsRng.fill_bytes(&mut base_nonce);

        for i in 0..5u64 {
            let chunk = format!("chunk data {i}");
            let ct = encrypt_chunk(&key, &base_nonce, i, chunk.as_bytes(), b"stream").unwrap();
            let pt = decrypt_chunk(&key, &base_nonce, i, &ct, b"stream").unwrap();
            assert_eq!(pt, chunk.as_bytes());
        }
    }

    #[test]
    fn test_invalid_key_size() {
        assert!(encrypt(&[0u8; 16], b"x", b"").is_err());
        assert!(decrypt(&[0u8; 16], &[0u8; 12], &[0u8; 16], b"").is_err());
    }

    #[test]
    fn test_invalid_nonce_size() {
        let mut key = [0u8; 32];
        OsRng.fill_bytes(&mut key);
        assert!(decrypt(&key, &[0u8; 8], &[0u8; 16], b"").is_err());
    }
}
