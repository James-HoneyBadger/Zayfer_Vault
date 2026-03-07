//! HB_Zayfer Core — Cryptographic operations library.
//!
//! This crate provides all cryptographic primitives and key management for the
//! HB_Zayfer encryption/decryption suite:
//!
//! - **AES-256-GCM** — fast authenticated encryption
//! - **ChaCha20-Poly1305** — modern authenticated encryption
//! - **RSA** — asymmetric encryption and signing (2048/4096)
//! - **Ed25519** — fast digital signatures
//! - **X25519** — elliptic-curve Diffie-Hellman key agreement
//! - **OpenPGP** — GPG-compatible operations via sequoia
//! - **Argon2/scrypt** — password-based key derivation
//!
//! File encryption uses the HBZF streaming format with 64 KiB chunks.

pub mod aes_gcm;
pub mod chacha20;
pub mod ed25519;
pub mod error;
pub mod format;
pub mod kdf;
pub mod keystore;
pub mod openpgp;
pub mod rsa;
pub mod x25519;

// Re-export commonly used types
pub use error::{HbError, HbResult};
pub use format::{SymmetricAlgorithm, KeyWrapping};
pub use keystore::{KeyStore, KeyAlgorithm, KeyMetadata, Contact};
pub use kdf::{KdfParams, KdfAlgorithm};
