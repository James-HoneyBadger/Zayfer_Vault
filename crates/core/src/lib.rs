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
pub mod audit;
pub mod backup;
pub mod chacha20;
pub mod compression;
pub mod config;
pub mod ed25519;
pub mod error;
pub mod format;
pub mod kdf;
pub mod keystore;
pub mod openpgp;
pub mod passgen;
pub mod platform;
pub mod qr;
pub mod rsa;
pub mod secure_mem;
pub mod services;
pub mod shamir;
pub mod shred;
pub mod stego;
pub mod x25519;

// Re-export commonly used types
pub use audit::{AuditEntry, AuditLogger, AuditOperation};
pub use backup::BackupManifest;
pub use config::{
    CliConfig, Config, GuiConfig, KdfPreset, DEFAULT_CHUNK_SIZE, MAX_CHUNK_SIZE, MIN_CHUNK_SIZE,
};
pub use error::{HbError, HbResult};
pub use format::{KeyWrapping, SymmetricAlgorithm};
pub use kdf::{KdfAlgorithm, KdfParams};
pub use keystore::{Contact, KeyAlgorithm, KeyExpiryStatus, KeyMetadata, KeyStore, KeyUsage};
pub use platform::{AppInfo, AppPaths};
pub use secure_mem::SecureBytes;
pub use services::{ConfigSnapshot, KeyGenerationSummary, WorkspaceSummary};
