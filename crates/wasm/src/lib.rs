//! HB_Zayfer WASM — Cryptographic operations for the browser.
//!
//! This crate provides JavaScript-callable bindings (via `wasm-bindgen`) for
//! the most-used HB_Zayfer crypto primitives.  It intentionally omits modules
//! that depend on system libraries (OpenPGP / sequoia, file I/O) and instead
//! exposes a focused API suitable for web applications.
//!
//! # Exposed operations
//!
//! | Function | Description |
//! |---|---|
//! | `aes_gcm_encrypt` / `aes_gcm_decrypt` | AES-256-GCM authenticated encryption |
//! | `chacha20_encrypt` / `chacha20_decrypt` | ChaCha20-Poly1305 encryption |
//! | `ed25519_keygen` / `ed25519_sign` / `ed25519_verify` | Ed25519 signatures |
//! | `x25519_keygen` / `x25519_dh` | X25519 Diffie-Hellman |
//! | `derive_key` | Argon2id key derivation |
//! | `sha256` | SHA-256 hash |
//!
//! # Building
//!
//! ```bash
//! # Install wasm-pack if needed
//! cargo install wasm-pack
//!
//! # Build for browser
//! wasm-pack build crates/wasm --target web --release
//! ```

use wasm_bindgen::prelude::*;

// ---------------------------------------------------------------------------
// AES-256-GCM
// ---------------------------------------------------------------------------

/// Encrypt `plaintext` with AES-256-GCM using the given 32-byte `key`.
/// Returns `nonce (12 bytes) || ciphertext+tag`.
#[wasm_bindgen]
pub fn aes_gcm_encrypt(key: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, JsError> {
    use aes_gcm::{aead::Aead, Aes256Gcm, KeyInit, Nonce};
    if key.len() != 32 {
        return Err(JsError::new("key must be 32 bytes"));
    }
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|e| JsError::new(&e.to_string()))?;
    let mut nonce_bytes = [0u8; 12];
    rand_core::OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);
    let ct = cipher
        .encrypt(nonce, plaintext)
        .map_err(|e| JsError::new(&e.to_string()))?;
    let mut out = Vec::with_capacity(12 + ct.len());
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&ct);
    Ok(out)
}

/// Decrypt AES-256-GCM ciphertext (format: `nonce (12) || ciphertext+tag`).
#[wasm_bindgen]
pub fn aes_gcm_decrypt(key: &[u8], data: &[u8]) -> Result<Vec<u8>, JsError> {
    use aes_gcm::{aead::Aead, Aes256Gcm, KeyInit, Nonce};
    if key.len() != 32 {
        return Err(JsError::new("key must be 32 bytes"));
    }
    if data.len() < 12 {
        return Err(JsError::new("data too short"));
    }
    let (nonce_bytes, ct) = data.split_at(12);
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|e| JsError::new(&e.to_string()))?;
    let nonce = Nonce::from_slice(nonce_bytes);
    cipher
        .decrypt(nonce, ct)
        .map_err(|e| JsError::new(&e.to_string()))
}

// ---------------------------------------------------------------------------
// ChaCha20-Poly1305
// ---------------------------------------------------------------------------

/// Encrypt `plaintext` with ChaCha20-Poly1305 using the given 32-byte `key`.
/// Returns `nonce (12 bytes) || ciphertext+tag`.
#[wasm_bindgen]
pub fn chacha20_encrypt(key: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, JsError> {
    use chacha20poly1305::{aead::Aead, ChaCha20Poly1305, KeyInit, Nonce};
    if key.len() != 32 {
        return Err(JsError::new("key must be 32 bytes"));
    }
    let cipher = ChaCha20Poly1305::new_from_slice(key).map_err(|e| JsError::new(&e.to_string()))?;
    let mut nonce_bytes = [0u8; 12];
    rand_core::OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);
    let ct = cipher
        .encrypt(nonce, plaintext)
        .map_err(|e| JsError::new(&e.to_string()))?;
    let mut out = Vec::with_capacity(12 + ct.len());
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&ct);
    Ok(out)
}

/// Decrypt ChaCha20-Poly1305 ciphertext (format: `nonce (12) || ciphertext+tag`).
#[wasm_bindgen]
pub fn chacha20_decrypt(key: &[u8], data: &[u8]) -> Result<Vec<u8>, JsError> {
    use chacha20poly1305::{aead::Aead, ChaCha20Poly1305, KeyInit, Nonce};
    if key.len() != 32 {
        return Err(JsError::new("key must be 32 bytes"));
    }
    if data.len() < 12 {
        return Err(JsError::new("data too short"));
    }
    let (nonce_bytes, ct) = data.split_at(12);
    let cipher = ChaCha20Poly1305::new_from_slice(key).map_err(|e| JsError::new(&e.to_string()))?;
    let nonce = Nonce::from_slice(nonce_bytes);
    cipher
        .decrypt(nonce, ct)
        .map_err(|e| JsError::new(&e.to_string()))
}

// ---------------------------------------------------------------------------
// Ed25519
// ---------------------------------------------------------------------------

use rand_core::{OsRng, RngCore};

/// Generate an Ed25519 keypair. Returns JSON `{"public": hex, "secret": hex}`.
#[wasm_bindgen]
pub fn ed25519_keygen() -> Result<String, JsError> {
    use ed25519_dalek::SigningKey;
    let sk = SigningKey::generate(&mut OsRng);
    let pk = sk.verifying_key();
    let obj = serde_json::json!({
        "public": hex::encode(pk.as_bytes()),
        "secret": hex::encode(sk.to_bytes()),
    });
    Ok(obj.to_string())
}

/// Sign `message` with an Ed25519 secret key (32 bytes). Returns 64-byte signature.
#[wasm_bindgen]
pub fn ed25519_sign(secret_key: &[u8], message: &[u8]) -> Result<Vec<u8>, JsError> {
    use ed25519_dalek::{Signer, SigningKey};
    let sk_bytes: [u8; 32] = secret_key
        .try_into()
        .map_err(|_| JsError::new("secret key must be 32 bytes"))?;
    let sk = SigningKey::from_bytes(&sk_bytes);
    let sig = sk.sign(message);
    Ok(sig.to_bytes().to_vec())
}

/// Verify an Ed25519 signature.
#[wasm_bindgen]
pub fn ed25519_verify(
    public_key: &[u8],
    message: &[u8],
    signature: &[u8],
) -> Result<bool, JsError> {
    use ed25519_dalek::{Signature, Verifier, VerifyingKey};
    let pk_bytes: [u8; 32] = public_key
        .try_into()
        .map_err(|_| JsError::new("public key must be 32 bytes"))?;
    let sig_bytes: [u8; 64] = signature
        .try_into()
        .map_err(|_| JsError::new("signature must be 64 bytes"))?;
    let vk = VerifyingKey::from_bytes(&pk_bytes).map_err(|e| JsError::new(&e.to_string()))?;
    let sig = Signature::from_bytes(&sig_bytes);
    Ok(vk.verify(message, &sig).is_ok())
}

// ---------------------------------------------------------------------------
// X25519
// ---------------------------------------------------------------------------

/// Generate an X25519 keypair. Returns JSON `{"public": hex, "secret": hex}`.
#[wasm_bindgen]
pub fn x25519_keygen() -> Result<String, JsError> {
    use x25519_dalek::{PublicKey, StaticSecret};
    let sk = StaticSecret::random_from_rng(OsRng);
    let pk = PublicKey::from(&sk);
    let obj = serde_json::json!({
        "public": hex::encode(pk.as_bytes()),
        "secret": hex::encode(sk.to_bytes()),
    });
    Ok(obj.to_string())
}

/// Perform X25519 Diffie-Hellman. Returns 32-byte shared secret.
#[wasm_bindgen]
pub fn x25519_dh(my_secret: &[u8], their_public: &[u8]) -> Result<Vec<u8>, JsError> {
    use x25519_dalek::{PublicKey, StaticSecret};
    let sk_bytes: [u8; 32] = my_secret
        .try_into()
        .map_err(|_| JsError::new("secret must be 32 bytes"))?;
    let pk_bytes: [u8; 32] = their_public
        .try_into()
        .map_err(|_| JsError::new("public key must be 32 bytes"))?;
    let sk = StaticSecret::from(sk_bytes);
    let pk = PublicKey::from(pk_bytes);
    let shared = sk.diffie_hellman(&pk);
    Ok(shared.as_bytes().to_vec())
}

// ---------------------------------------------------------------------------
// Key Derivation (Argon2id)
// ---------------------------------------------------------------------------

/// Derive a 32-byte key from a password and 16-byte salt using Argon2id.
#[wasm_bindgen]
pub fn derive_key(password: &str, salt: &[u8]) -> Result<Vec<u8>, JsError> {
    use argon2::Argon2;
    if password.is_empty() {
        return Err(JsError::new("password must not be empty"));
    }
    if salt.len() < 8 {
        return Err(JsError::new("salt must be at least 8 bytes"));
    }
    let mut out = vec![0u8; 32];
    Argon2::default()
        .hash_password_into(password.as_bytes(), salt, &mut out)
        .map_err(|e| JsError::new(&e.to_string()))?;
    Ok(out)
}

// ---------------------------------------------------------------------------
// SHA-256
// ---------------------------------------------------------------------------

/// Compute SHA-256 hash. Returns 32-byte digest.
#[wasm_bindgen]
pub fn sha256(data: &[u8]) -> Vec<u8> {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().to_vec()
}

// ---------------------------------------------------------------------------
// Utilities
// ---------------------------------------------------------------------------

/// HB_Zayfer WASM module version.
#[wasm_bindgen]
pub fn version() -> String {
    env!("CARGO_PKG_VERSION").to_string()
}

/// Generate `n` random bytes (max 1 MiB).
#[wasm_bindgen]
pub fn random_bytes(n: usize) -> Result<Vec<u8>, JsError> {
    if n > 1_048_576 {
        return Err(JsError::new("n must be at most 1048576 (1 MiB)"));
    }
    let mut buf = vec![0u8; n];
    OsRng.fill_bytes(&mut buf);
    Ok(buf)
}
