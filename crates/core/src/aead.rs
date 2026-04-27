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
