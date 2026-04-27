//! Shared AEAD helper that backs both [`aes_gcm`](crate::aes_gcm) and
//! [`chacha20`](crate::chacha20).
//!
//! AES-256-GCM and ChaCha20-Poly1305 expose identical interfaces in
//! [`aead`]: 32-byte key, 12-byte nonce, 16-byte tag, and an `Aead` impl
//! over [`aead::Payload`]. Prior to this module, those two facts were
//! reproduced almost verbatim in `aes_gcm.rs` and `chacha20.rs` (~340 LOC of
//! duplicate logic). Centralising the implementation here:
//!
//! * makes per-chunk nonce derivation and AAD framing impossible to drift
//!   between ciphers,
//! * gives the rest of the crate (`format.rs`, `services.rs`, bindings) a
//!   single, audited code path for streaming encryption,
//! * keeps the per-cipher modules as thin re-exports for backward compat.

use aead::{Aead, KeyInit, Payload};
use rand::RngCore;
use rand_core::OsRng;

use crate::error::{HbError, HbResult};

/// Both supported AEADs use a 32-byte key.
pub const KEY_SIZE: usize = 32;
/// Both supported AEADs use a 96-bit (12 byte) nonce.
pub const NONCE_SIZE: usize = 12;
/// Both supported AEADs produce a 128-bit (16 byte) authentication tag.
pub const TAG_SIZE: usize = 16;

/// Maximum chunk index permitted by the per-chunk nonce derivation.
///
/// The derivation XORs the 8-byte little-endian chunk index into the trailing
/// 8 bytes of the base nonce. Capping the index at `2^32` guarantees that the
/// XOR pattern cannot cause two chunks under the same base nonce to share a
/// final nonce.
pub const MAX_CHUNK_INDEX: u64 = 1u64 << 32;

/// Identifies which AEAD a generic call is operating against; used purely so
/// that error messages still refer to the user-visible cipher name.
#[derive(Copy, Clone)]
pub enum CipherKind {
    AesGcm,
    ChaCha20Poly1305,
}

impl CipherKind {
    fn err(self, msg: impl Into<String>) -> HbError {
        match self {
            CipherKind::AesGcm => HbError::AesGcm(msg.into()),
            CipherKind::ChaCha20Poly1305 => HbError::ChaCha20(msg.into()),
        }
    }
}

fn check_key(kind: CipherKind, key: &[u8]) -> HbResult<()> {
    if key.len() != KEY_SIZE {
        return Err(kind.err(format!("Key must be {KEY_SIZE} bytes, got {}", key.len())));
    }
    Ok(())
}

fn check_nonce(kind: CipherKind, nonce: &[u8]) -> HbResult<()> {
    if nonce.len() != NONCE_SIZE {
        return Err(kind.err(format!(
            "Nonce must be {NONCE_SIZE} bytes, got {}",
            nonce.len()
        )));
    }
    Ok(())
}

fn check_chunk_index(kind: CipherKind, index: u64) -> HbResult<()> {
    if index >= MAX_CHUNK_INDEX {
        return Err(kind.err("Chunk index exceeds maximum (nonce space exhaustion)"));
    }
    Ok(())
}

/// Derive a per-chunk nonce by XORing the chunk index into the base nonce.
fn derive_chunk_nonce(base: &[u8; NONCE_SIZE], index: u64) -> [u8; NONCE_SIZE] {
    let mut nonce = *base;
    let idx_bytes = index.to_le_bytes();
    for i in 0..8 {
        nonce[4 + i] ^= idx_bytes[i];
    }
    nonce
}

/// Append the chunk index to the supplied AAD so reordering is detected.
fn chunked_aad(aad: &[u8], index: u64) -> Vec<u8> {
    let mut out = Vec::with_capacity(aad.len() + 8);
    out.extend_from_slice(aad);
    out.extend_from_slice(&index.to_le_bytes());
    out
}

/// Generic encrypt with a freshly generated random nonce.
pub fn encrypt<C>(
    kind: CipherKind,
    key: &[u8],
    plaintext: &[u8],
    aad: &[u8],
) -> HbResult<(Vec<u8>, Vec<u8>)>
where
    C: KeyInit + Aead,
{
    check_key(kind, key)?;
    let cipher = C::new_from_slice(key).map_err(|e| kind.err(format!("Invalid key: {e}")))?;

    let mut nonce_bytes = [0u8; NONCE_SIZE];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = aead::Nonce::<C>::from_slice(&nonce_bytes);

    let ct = cipher
        .encrypt(
            nonce,
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|e| kind.err(format!("Encryption failed: {e}")))?;

    Ok((nonce_bytes.to_vec(), ct))
}

/// Generic decrypt.
pub fn decrypt<C>(
    kind: CipherKind,
    key: &[u8],
    nonce: &[u8],
    ciphertext: &[u8],
    aad: &[u8],
) -> HbResult<Vec<u8>>
where
    C: KeyInit + Aead,
{
    check_key(kind, key)?;
    check_nonce(kind, nonce)?;
    let cipher = C::new_from_slice(key).map_err(|e| kind.err(format!("Invalid key: {e}")))?;
    let nonce = aead::Nonce::<C>::from_slice(nonce);
    cipher
        .decrypt(
            nonce,
            Payload {
                msg: ciphertext,
                aad,
            },
        )
        .map_err(|_| HbError::AuthenticationFailed)
}

/// Generic streaming chunk encrypt.
pub fn encrypt_chunk<C>(
    kind: CipherKind,
    key: &[u8],
    base_nonce: &[u8; NONCE_SIZE],
    chunk_index: u64,
    chunk: &[u8],
    aad: &[u8],
) -> HbResult<Vec<u8>>
where
    C: KeyInit + Aead,
{
    check_chunk_index(kind, chunk_index)?;
    let cipher = C::new_from_slice(key).map_err(|e| kind.err(format!("Invalid key: {e}")))?;

    let nonce_bytes = derive_chunk_nonce(base_nonce, chunk_index);
    let nonce = aead::Nonce::<C>::from_slice(&nonce_bytes);
    let full_aad = chunked_aad(aad, chunk_index);

    cipher
        .encrypt(
            nonce,
            Payload {
                msg: chunk,
                aad: &full_aad,
            },
        )
        .map_err(|e| kind.err(format!("Chunk encryption failed: {e}")))
}

/// Generic streaming chunk decrypt.
pub fn decrypt_chunk<C>(
    kind: CipherKind,
    key: &[u8],
    base_nonce: &[u8; NONCE_SIZE],
    chunk_index: u64,
    ciphertext: &[u8],
    aad: &[u8],
) -> HbResult<Vec<u8>>
where
    C: KeyInit + Aead,
{
    check_chunk_index(kind, chunk_index)?;
    let cipher = C::new_from_slice(key).map_err(|e| kind.err(format!("Invalid key: {e}")))?;

    let nonce_bytes = derive_chunk_nonce(base_nonce, chunk_index);
    let nonce = aead::Nonce::<C>::from_slice(&nonce_bytes);
    let full_aad = chunked_aad(aad, chunk_index);

    cipher
        .decrypt(
            nonce,
            Payload {
                msg: ciphertext,
                aad: &full_aad,
            },
        )
        .map_err(|_| HbError::AuthenticationFailed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ::aes_gcm::Aes256Gcm;
    use ::chacha20poly1305::ChaCha20Poly1305;

    fn key32() -> [u8; KEY_SIZE] {
        let mut k = [0u8; KEY_SIZE];
        for (i, b) in k.iter_mut().enumerate() {
            *b = i as u8;
        }
        k
    }

    #[test]
    fn derive_chunk_nonce_unique_per_index() {
        let base = [7u8; NONCE_SIZE];
        let n0 = derive_chunk_nonce(&base, 0);
        let n1 = derive_chunk_nonce(&base, 1);
        let n2 = derive_chunk_nonce(&base, MAX_CHUNK_INDEX - 1);
        assert_ne!(n0, n1);
        assert_ne!(n0, n2);
        assert_ne!(n1, n2);
        // Index 0 must leave the base nonce unchanged.
        assert_eq!(n0, base);
    }

    #[test]
    fn chunked_aad_appends_index_le() {
        let out = chunked_aad(b"abc", 0x0102030405060708);
        assert_eq!(&out[..3], b"abc");
        assert_eq!(&out[3..], &0x0102030405060708u64.to_le_bytes());
    }

    #[test]
    fn check_key_rejects_short_key() {
        let err = check_key(CipherKind::AesGcm, &[0u8; 16]).unwrap_err();
        assert!(err.to_string().contains("Key must be"));
    }

    #[test]
    fn check_nonce_rejects_wrong_size() {
        assert!(check_nonce(CipherKind::ChaCha20Poly1305, &[0u8; 11]).is_err());
        assert!(check_nonce(CipherKind::ChaCha20Poly1305, &[0u8; 13]).is_err());
        assert!(check_nonce(CipherKind::ChaCha20Poly1305, &[0u8; 12]).is_ok());
    }

    #[test]
    fn check_chunk_index_rejects_overflow() {
        assert!(check_chunk_index(CipherKind::AesGcm, 0).is_ok());
        assert!(check_chunk_index(CipherKind::AesGcm, MAX_CHUNK_INDEX - 1).is_ok());
        assert!(check_chunk_index(CipherKind::AesGcm, MAX_CHUNK_INDEX).is_err());
    }

    #[test]
    fn aes_gcm_roundtrip_via_generic_path() {
        let key = key32();
        let (nonce, ct) =
            encrypt::<Aes256Gcm>(CipherKind::AesGcm, &key, b"hello", b"meta").unwrap();
        let pt = decrypt::<Aes256Gcm>(CipherKind::AesGcm, &key, &nonce, &ct, b"meta").unwrap();
        assert_eq!(pt, b"hello");
    }

    #[test]
    fn chacha_roundtrip_via_generic_path() {
        let key = key32();
        let (nonce, ct) =
            encrypt::<ChaCha20Poly1305>(CipherKind::ChaCha20Poly1305, &key, b"world", b"hdr")
                .unwrap();
        let pt =
            decrypt::<ChaCha20Poly1305>(CipherKind::ChaCha20Poly1305, &key, &nonce, &ct, b"hdr")
                .unwrap();
        assert_eq!(pt, b"world");
    }

    #[test]
    fn decrypt_with_wrong_aad_fails_auth() {
        let key = key32();
        let (nonce, ct) =
            encrypt::<Aes256Gcm>(CipherKind::AesGcm, &key, b"data", b"good-aad").unwrap();
        let err =
            decrypt::<Aes256Gcm>(CipherKind::AesGcm, &key, &nonce, &ct, b"bad-aad").unwrap_err();
        assert!(matches!(err, HbError::AuthenticationFailed));
    }

    #[test]
    fn decrypt_with_tampered_ciphertext_fails_auth() {
        let key = key32();
        let (nonce, mut ct) =
            encrypt::<Aes256Gcm>(CipherKind::AesGcm, &key, b"data", b"aad").unwrap();
        ct[0] ^= 0x01;
        let err = decrypt::<Aes256Gcm>(CipherKind::AesGcm, &key, &nonce, &ct, b"aad").unwrap_err();
        assert!(matches!(err, HbError::AuthenticationFailed));
    }

    #[test]
    fn chunk_reorder_is_detected() {
        let key = key32();
        let base = [9u8; NONCE_SIZE];
        let c0 =
            encrypt_chunk::<Aes256Gcm>(CipherKind::AesGcm, &key, &base, 0, b"first", b"").unwrap();
        let c1 =
            encrypt_chunk::<Aes256Gcm>(CipherKind::AesGcm, &key, &base, 1, b"second", b"").unwrap();
        // Decrypting chunk 1 ciphertext at index 0 must fail (nonce + AAD bound).
        let err =
            decrypt_chunk::<Aes256Gcm>(CipherKind::AesGcm, &key, &base, 0, &c1, b"").unwrap_err();
        assert!(matches!(err, HbError::AuthenticationFailed));
        // Same for chunk 0 ciphertext at index 1.
        let err =
            decrypt_chunk::<Aes256Gcm>(CipherKind::AesGcm, &key, &base, 1, &c0, b"").unwrap_err();
        assert!(matches!(err, HbError::AuthenticationFailed));
    }

    #[test]
    fn chunk_roundtrip_chacha_independent_of_aes() {
        let key = key32();
        let base = [3u8; NONCE_SIZE];
        let ct = encrypt_chunk::<ChaCha20Poly1305>(
            CipherKind::ChaCha20Poly1305,
            &key,
            &base,
            42,
            b"payload",
            b"hdr",
        )
        .unwrap();
        let pt = decrypt_chunk::<ChaCha20Poly1305>(
            CipherKind::ChaCha20Poly1305,
            &key,
            &base,
            42,
            &ct,
            b"hdr",
        )
        .unwrap();
        assert_eq!(pt, b"payload");
    }

    #[test]
    fn encrypt_with_wrong_key_size_errors_with_cipher_label() {
        let bad_key = [0u8; 16];
        let err = encrypt::<Aes256Gcm>(CipherKind::AesGcm, &bad_key, b"x", b"").unwrap_err();
        // CipherKind labels error so the user can tell which crate misbehaved.
        assert!(matches!(err, HbError::AesGcm(_)));
        let err = encrypt::<ChaCha20Poly1305>(CipherKind::ChaCha20Poly1305, &bad_key, b"x", b"")
            .unwrap_err();
        assert!(matches!(err, HbError::ChaCha20(_)));
    }
}
