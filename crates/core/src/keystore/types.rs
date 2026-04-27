//! Keystore data types: key metadata, usage constraints, expiry status,
//! contacts, and the on-disk index containers.
//!
//! Split out of `keystore/mod.rs` in Phase B2 so the file housing the
//! [`KeyStore`](super::KeyStore) implementation only owns I/O and key
//! lifecycle logic. All items here are re-exported from `super` to keep
//! the public surface (`hb_zayfer_core::keystore::*`) unchanged.

use std::collections::HashMap;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::error::{HbError, HbResult};

/// Algorithm type for a stored key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum KeyAlgorithm {
    Rsa2048,
    Rsa4096,
    Ed25519,
    X25519,
    Pgp,
}

impl std::fmt::Display for KeyAlgorithm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            KeyAlgorithm::Rsa2048 => write!(f, "RSA-2048"),
            KeyAlgorithm::Rsa4096 => write!(f, "RSA-4096"),
            KeyAlgorithm::Ed25519 => write!(f, "Ed25519"),
            KeyAlgorithm::X25519 => write!(f, "X25519"),
            KeyAlgorithm::Pgp => write!(f, "PGP"),
        }
    }
}

/// Metadata for a key stored in the keyring.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyMetadata {
    pub fingerprint: String,
    pub algorithm: KeyAlgorithm,
    pub label: String,
    pub created_at: DateTime<Utc>,
    pub has_private: bool,
    pub has_public: bool,
    /// Allowed usage constraints for this key.
    /// If empty or `None`, the key can be used for any operation its algorithm
    /// supports. When set, operations not in the list are rejected.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allowed_usages: Option<Vec<KeyUsage>>,
    /// Optional expiry date. The key should be rejected after this timestamp.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<DateTime<Utc>>,
}

/// Permitted key usage operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum KeyUsage {
    /// Key may be used for encryption / key wrapping.
    Encrypt,
    /// Key may be used for decryption / key unwrapping.
    Decrypt,
    /// Key may be used for digital signatures.
    Sign,
    /// Key may be used for signature verification.
    Verify,
    /// Key may be used for Diffie-Hellman key agreement.
    KeyAgreement,
}

/// Status returned by [`super::KeyStore::check_expiring_keys`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyExpiryStatus {
    /// The key has already passed its expiry date.
    Expired,
    /// The key will expire within the configured warning window.
    ExpiringSoon { days_left: u32 },
}

impl KeyMetadata {
    /// Returns `Ok(())` if the key is allowed for the given `usage`, or an
    /// error describing why it is not.
    pub fn check_usage(&self, usage: KeyUsage) -> HbResult<()> {
        // Check expiry first
        if let Some(exp) = self.expires_at {
            if Utc::now() > exp {
                return Err(HbError::Config(format!(
                    "Key '{}' expired on {}",
                    self.fingerprint,
                    exp.to_rfc3339()
                )));
            }
        }
        // Check usage constraints
        if let Some(ref usages) = self.allowed_usages {
            if !usages.contains(&usage) {
                return Err(HbError::Config(format!(
                    "Key '{}' is not permitted for {:?} (allowed: {:?})",
                    self.fingerprint, usage, usages
                )));
            }
        }
        Ok(())
    }
}

/// A contact in the address book.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Contact {
    pub name: String,
    pub email: Option<String>,
    pub key_fingerprints: Vec<String>,
    pub notes: Option<String>,
    pub created_at: DateTime<Utc>,
}

/// The keyring index file.
#[derive(Debug, Default, Serialize, Deserialize)]
pub(crate) struct KeyringIndex {
    pub keys: HashMap<String, KeyMetadata>,
}

/// The contacts file.
#[derive(Debug, Default, Serialize, Deserialize)]
pub(crate) struct ContactsStore {
    pub contacts: HashMap<String, Contact>,
}
