//! ChaCha20-Poly1305 authenticated encryption.
//!
//! All real work lives in [`crate::aead`]; this module is a thin
//! cipher-specific facade preserving the historical public API.

use chacha20poly1305::ChaCha20Poly1305;

use crate::aead as shared;
use crate::error::HbResult;

/// Nonce size for ChaCha20-Poly1305 (96 bits / 12 bytes).
pub const CHACHA20_NONCE_SIZE: usize = shared::NONCE_SIZE;
/// Key size for ChaCha20-Poly1305 (256 bits / 32 bytes).
pub const CHACHA20_KEY_SIZE: usize = shared::KEY_SIZE;
/// Authentication tag size (128 bits / 16 bytes).
pub const CHACHA20_TAG_SIZE: usize = shared::TAG_SIZE;

const KIND: shared::CipherKind = shared::CipherKind::ChaCha20Poly1305;

/// Encrypt plaintext with ChaCha20-Poly1305. Returns `(nonce, ciphertext_with_tag)`.
pub fn encrypt(key: &[u8], plaintext: &[u8], aad: &[u8]) -> HbResult<(Vec<u8>, Vec<u8>)> {
    shared::encrypt::<ChaCha20Poly1305>(KIND, key, plaintext, aad)
}

/// Decrypt ciphertext with ChaCha20-Poly1305.
pub fn decrypt(key: &[u8], nonce: &[u8], ciphertext: &[u8], aad: &[u8]) -> HbResult<Vec<u8>> {
    shared::decrypt::<ChaCha20Poly1305>(KIND, key, nonce, ciphertext, aad)
}

/// Streaming chunk encrypt with derived per-chunk nonce.
pub fn encrypt_chunk(
    key: &[u8],
    base_nonce: &[u8; CHACHA20_NONCE_SIZE],
    chunk_index: u64,
    chunk: &[u8],
    aad: &[u8],
) -> HbResult<Vec<u8>> {
    shared::encrypt_chunk::<ChaCha20Poly1305>(KIND, key, base_nonce, chunk_index, chunk, aad)
}

/// Streaming chunk decrypt with derived per-chunk nonce.
pub fn decrypt_chunk(
    key: &[u8],
    base_nonce: &[u8; CHACHA20_NONCE_SIZE],
    chunk_index: u64,
    ciphertext: &[u8],
    aad: &[u8],
) -> HbResult<Vec<u8>> {
    shared::decrypt_chunk::<ChaCha20Poly1305>(KIND, key, base_nonce, chunk_index, ciphertext, aad)
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
        assert!(decrypt(&key, &nonce, &ciphertext, b"").is_err());
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

    #[test]
    fn test_invalid_key_size() {
        assert!(encrypt(&[0u8; 16], b"x", b"").is_err());
    }

    #[test]
    fn test_invalid_nonce_size() {
        let mut key = [0u8; 32];
        OsRng.fill_bytes(&mut key);
        assert!(decrypt(&key, &[0u8; 8], &[0u8; 16], b"").is_err());
    }
}
