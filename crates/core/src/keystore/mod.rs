//! Key storage and contact management.
//!
//! Manages keys on disk at `~/.hb_zayfer/` with the structure:
//! ```text
//! ~/.hb_zayfer/
//!   keys/private/<fingerprint>.key  (encrypted)
//!   keys/public/<fingerprint>.pub
//!   keyring.json
//!   contacts.json
//!   config.toml
//! ```
//!
//! Module layout (Phase B2 split):
//! - [`types`] — data types (`KeyAlgorithm`, `KeyMetadata`, `KeyUsage`,
//!   `KeyExpiryStatus`, `Contact`, and the on-disk index containers).
//! - [`format`] — public-key fingerprinting + format detection.
//! - this file — the [`KeyStore`] struct and its I/O / lifecycle methods.

mod format;
mod types;

pub use format::{compute_fingerprint, detect_key_format, KeyFormat};
pub use types::{Contact, KeyAlgorithm, KeyExpiryStatus, KeyMetadata, KeyUsage};
use types::{ContactsStore, KeyringIndex};

use std::fs;
use std::path::{Path, PathBuf};

use chrono::{DateTime, Utc};

use crate::aes_gcm;
use crate::error::{HbError, HbResult};
use crate::kdf::{self, KdfParams};

/// The KeyStore manages all key operations on disk.
pub struct KeyStore {
    base_path: PathBuf,
    index: KeyringIndex,
    contacts: ContactsStore,
}

impl KeyStore {
    /// Open or create a keystore at the default location.
    ///
    /// Checks `HB_ZAYFER_HOME` env-var first, then falls back to `~/.hb_zayfer/`.
    pub fn open_default() -> HbResult<Self> {
        if let Ok(custom) = std::env::var("HB_ZAYFER_HOME") {
            return Self::open(PathBuf::from(custom));
        }
        let home =
            dirs::home_dir().ok_or_else(|| HbError::Io("Home directory not found".into()))?;
        Self::open(home.join(".hb_zayfer"))
    }

    /// Open or create a keystore at the specified path.
    pub fn open(base_path: PathBuf) -> HbResult<Self> {
        // Create directory structure
        fs::create_dir_all(base_path.join("keys/private"))?;
        fs::create_dir_all(base_path.join("keys/public"))?;

        // Set permissions on private key directory (Unix only)
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let perms = fs::Permissions::from_mode(0o700);
            let _ = fs::set_permissions(base_path.join("keys/private"), perms);
        }

        // Load or create index
        let index_path = base_path.join("keyring.json");
        let index = if index_path.exists() {
            let data = fs::read_to_string(&index_path)?;
            serde_json::from_str(&data)?
        } else {
            KeyringIndex::default()
        };

        // Load or create contacts
        let contacts_path = base_path.join("contacts.json");
        let contacts = if contacts_path.exists() {
            let data = fs::read_to_string(&contacts_path)?;
            serde_json::from_str(&data)?
        } else {
            ContactsStore::default()
        };

        Ok(Self {
            base_path,
            index,
            contacts,
        })
    }

    /// Atomically save data to a file using write-then-rename.
    fn atomic_write(path: &Path, data: &[u8]) -> HbResult<()> {
        let tmp = path.with_extension("tmp");
        fs::write(&tmp, data)?;
        fs::rename(&tmp, path)?;
        Ok(())
    }

    /// Save the keyring index to disk (atomic).
    fn save_index(&self) -> HbResult<()> {
        let data = serde_json::to_string_pretty(&self.index)?;
        Self::atomic_write(&self.base_path.join("keyring.json"), data.as_bytes())?;
        Ok(())
    }

    /// Save contacts to disk (atomic).
    fn save_contacts(&self) -> HbResult<()> {
        let data = serde_json::to_string_pretty(&self.contacts)?;
        Self::atomic_write(&self.base_path.join("contacts.json"), data.as_bytes())?;
        Ok(())
    }

    /// Get the base path.
    pub fn base_path(&self) -> &Path {
        &self.base_path
    }

    // -- Key storage --

    /// Private key envelope version.
    ///
    /// Version 2 stores KDF metadata so key decryption works even if
    /// global defaults change:
    /// ```text
    /// [1B] envelope version (0x02)
    /// [1B] KDF algorithm ID
    /// [12B] KDF params (same layout as HBZF header)
    /// [16B] salt
    /// [12B] nonce
    /// [...] AES-256-GCM ciphertext
    /// ```
    const KEY_ENVELOPE_VERSION: u8 = 0x02;

    /// Store a private key (encrypted with passphrase).
    pub fn store_private_key(
        &mut self,
        fingerprint: &str,
        key_bytes: &[u8],
        passphrase: &[u8],
        algorithm: KeyAlgorithm,
        label: &str,
    ) -> HbResult<()> {
        // Derive encryption key from passphrase
        let kdf_params = KdfParams::default();
        let salt = kdf::generate_salt(16);
        let enc_key = kdf::derive_key(passphrase, &salt, &kdf_params)?;

        // Encrypt the private key with AES-256-GCM
        let (nonce, ciphertext) = aes_gcm::encrypt(&enc_key, key_bytes, fingerprint.as_bytes())?;

        // Build versioned envelope: version(1) + kdf_id(1) + kdf_params(12) + salt(16) + nonce(12) + ciphertext
        let mut envelope = Vec::new();
        envelope.push(Self::KEY_ENVELOPE_VERSION);
        envelope.push(kdf_params.algorithm().id());
        match &kdf_params {
            KdfParams::Argon2id(p) => {
                envelope.extend_from_slice(&p.m_cost.to_le_bytes());
                envelope.extend_from_slice(&p.t_cost.to_le_bytes());
                envelope.extend_from_slice(&p.p_cost.to_le_bytes());
            }
            KdfParams::Scrypt(p) => {
                envelope.push(p.log_n);
                envelope.extend_from_slice(&[0u8; 3]); // padding
                envelope.extend_from_slice(&p.r.to_le_bytes());
                envelope.extend_from_slice(&p.p.to_le_bytes());
            }
        }
        envelope.extend_from_slice(&salt);
        envelope.extend_from_slice(&nonce);
        envelope.extend_from_slice(&ciphertext);

        let key_path = self
            .base_path
            .join("keys/private")
            .join(format!("{fingerprint}.key"));
        fs::write(&key_path, &envelope)?;

        // Set file permissions (Unix only)
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let perms = fs::Permissions::from_mode(0o600);
            let _ = fs::set_permissions(&key_path, perms);
        }

        // Update or create index entry
        let entry = self
            .index
            .keys
            .entry(fingerprint.to_string())
            .or_insert_with(|| KeyMetadata {
                fingerprint: fingerprint.to_string(),
                algorithm: algorithm.clone(),
                label: label.to_string(),
                created_at: Utc::now(),
                has_private: false,
                has_public: false,
                allowed_usages: None,
                expires_at: None,
            });
        entry.has_private = true;
        entry.algorithm = algorithm;
        if !label.is_empty() {
            entry.label = label.to_string();
        }

        self.save_index()?;
        Ok(())
    }

    /// Store a public key.
    pub fn store_public_key(
        &mut self,
        fingerprint: &str,
        key_bytes: &[u8],
        algorithm: KeyAlgorithm,
        label: &str,
    ) -> HbResult<()> {
        let key_path = self
            .base_path
            .join("keys/public")
            .join(format!("{fingerprint}.pub"));
        fs::write(&key_path, key_bytes)?;

        let entry = self
            .index
            .keys
            .entry(fingerprint.to_string())
            .or_insert_with(|| KeyMetadata {
                fingerprint: fingerprint.to_string(),
                algorithm: algorithm.clone(),
                label: label.to_string(),
                created_at: Utc::now(),
                has_private: false,
                has_public: false,
                allowed_usages: None,
                expires_at: None,
            });
        entry.has_public = true;
        entry.algorithm = algorithm;
        if !label.is_empty() {
            entry.label = label.to_string();
        }

        self.save_index()?;
        Ok(())
    }

    /// Load an encrypted private key, decrypting with the passphrase.
    ///
    /// Supports both v1 (legacy: no header) and v2 (versioned with embedded KDF params).
    pub fn load_private_key(&self, fingerprint: &str, passphrase: &[u8]) -> HbResult<Vec<u8>> {
        let key_path = self
            .base_path
            .join("keys/private")
            .join(format!("{fingerprint}.key"));
        if !key_path.exists() {
            return Err(HbError::KeyNotFound(fingerprint.to_string()));
        }

        let envelope = fs::read(&key_path)?;

        // Detect envelope version
        let (kdf_params, salt, nonce, ciphertext) =
            if !envelope.is_empty() && envelope[0] == Self::KEY_ENVELOPE_VERSION {
                // V2 envelope: version(1) + kdf_id(1) + kdf_params(12) + salt(16) + nonce(12) + ct
                if envelope.len() < 1 + 1 + 12 + 16 + 12 {
                    return Err(HbError::InvalidFormat("V2 key envelope too short".into()));
                }
                let kdf_id = envelope[1];
                let kdf_param_bytes = &envelope[2..14];
                let kdf_p = match kdf::KdfAlgorithm::from_id(kdf_id)? {
                    kdf::KdfAlgorithm::Argon2id => {
                        let m = u32::from_le_bytes(kdf_param_bytes[0..4].try_into().unwrap());
                        let t = u32::from_le_bytes(kdf_param_bytes[4..8].try_into().unwrap());
                        let p = u32::from_le_bytes(kdf_param_bytes[8..12].try_into().unwrap());
                        KdfParams::Argon2id(kdf::Argon2Params {
                            m_cost: m,
                            t_cost: t,
                            p_cost: p,
                        })
                    }
                    kdf::KdfAlgorithm::Scrypt => {
                        let log_n = kdf_param_bytes[0];
                        let r = u32::from_le_bytes(kdf_param_bytes[4..8].try_into().unwrap());
                        let p = u32::from_le_bytes(kdf_param_bytes[8..12].try_into().unwrap());
                        KdfParams::Scrypt(kdf::ScryptParams { log_n, r, p })
                    }
                };
                let salt = &envelope[14..30];
                let nonce = &envelope[30..42];
                let ciphertext = &envelope[42..];
                (kdf_p, salt, nonce, ciphertext)
            } else {
                // V1 (legacy) envelope: salt(16) + nonce(12) + ciphertext
                if envelope.len() < 28 {
                    return Err(HbError::InvalidFormat("Key file too short".into()));
                }
                let salt = &envelope[..16];
                let nonce = &envelope[16..28];
                let ciphertext = &envelope[28..];
                (KdfParams::default(), salt, nonce, ciphertext)
            };

        let enc_key = kdf::derive_key(passphrase, salt, &kdf_params)?;

        aes_gcm::decrypt(&enc_key, nonce, ciphertext, fingerprint.as_bytes())
            .map_err(|_| HbError::InvalidPassphrase)
    }

    /// Load a public key.
    pub fn load_public_key(&self, fingerprint: &str) -> HbResult<Vec<u8>> {
        let key_path = self
            .base_path
            .join("keys/public")
            .join(format!("{fingerprint}.pub"));
        if !key_path.exists() {
            return Err(HbError::KeyNotFound(fingerprint.to_string()));
        }
        Ok(fs::read(&key_path)?)
    }

    /// List all keys in the keyring.
    pub fn list_keys(&self) -> Vec<&KeyMetadata> {
        self.index.keys.values().collect()
    }

    /// Get metadata for a specific key.
    pub fn get_key_metadata(&self, fingerprint: &str) -> Option<&KeyMetadata> {
        self.index.keys.get(fingerprint)
    }

    /// Find keys by label (partial match).
    pub fn find_keys_by_label(&self, query: &str) -> Vec<&KeyMetadata> {
        let query_lower = query.to_lowercase();
        self.index
            .keys
            .values()
            .filter(|m| m.label.to_lowercase().contains(&query_lower))
            .collect()
    }

    /// Delete a key (both private and public).
    ///
    /// Private key files are securely shredded (overwritten before deletion)
    /// to prevent recovery of key material from disk.
    pub fn delete_key(&mut self, fingerprint: &str) -> HbResult<()> {
        let priv_path = self
            .base_path
            .join("keys/private")
            .join(format!("{fingerprint}.key"));
        let pub_path = self
            .base_path
            .join("keys/public")
            .join(format!("{fingerprint}.pub"));

        if priv_path.exists() {
            // Securely shred private key files to prevent recovery
            crate::shred::shred_file(&priv_path, crate::shred::DEFAULT_PASSES)?;
        }
        if pub_path.exists() {
            fs::remove_file(&pub_path)?;
        }

        self.index.keys.remove(fingerprint);
        self.save_index()?;

        // Remove from any contacts
        for contact in self.contacts.contacts.values_mut() {
            contact.key_fingerprints.retain(|fp| fp != fingerprint);
        }
        self.save_contacts()?;

        Ok(())
    }

    /// Set the allowed key usage constraints for a key.
    ///
    /// Pass `None` to remove all constraints (allow any usage).
    pub fn set_key_usage(
        &mut self,
        fingerprint: &str,
        usages: Option<Vec<KeyUsage>>,
    ) -> HbResult<()> {
        let meta = self
            .index
            .keys
            .get_mut(fingerprint)
            .ok_or_else(|| HbError::KeyNotFound(fingerprint.to_string()))?;
        meta.allowed_usages = usages;
        self.save_index()?;
        Ok(())
    }

    /// Set the expiry date for a key.
    ///
    /// Pass `None` to remove the expiry.
    pub fn set_key_expiry(
        &mut self,
        fingerprint: &str,
        expires_at: Option<DateTime<Utc>>,
    ) -> HbResult<()> {
        let meta = self
            .index
            .keys
            .get_mut(fingerprint)
            .ok_or_else(|| HbError::KeyNotFound(fingerprint.to_string()))?;
        meta.expires_at = expires_at;
        self.save_index()?;
        Ok(())
    }

    /// Return keys that have already expired or will expire within the given
    /// number of days.
    ///
    /// Each result is `(metadata, status)` where `status` is:
    /// - `KeyExpiryStatus::Expired` for keys past their expiry date
    /// - `KeyExpiryStatus::ExpiringSoon { days_left }` for keys expiring within
    ///   `warning_days`
    pub fn check_expiring_keys(&self, warning_days: u32) -> Vec<(&KeyMetadata, KeyExpiryStatus)> {
        let now = Utc::now();
        let warning_horizon = now + chrono::Duration::days(warning_days as i64);
        let mut results = Vec::new();

        for meta in self.index.keys.values() {
            if let Some(exp) = meta.expires_at {
                if exp <= now {
                    results.push((meta, KeyExpiryStatus::Expired));
                } else if exp <= warning_horizon {
                    let days_left = (exp - now).num_days().max(0) as u32;
                    results.push((meta, KeyExpiryStatus::ExpiringSoon { days_left }));
                }
            }
        }

        // Sort: expired first, then by days remaining
        results.sort_by_key(|(_, status)| match status {
            KeyExpiryStatus::Expired => 0,
            KeyExpiryStatus::ExpiringSoon { days_left } => *days_left + 1,
        });

        results
    }

    // -- Contact management --

    /// Add a contact.
    pub fn add_contact(
        &mut self,
        name: &str,
        email: Option<&str>,
        notes: Option<&str>,
    ) -> HbResult<()> {
        if self.contacts.contacts.contains_key(name) {
            return Err(HbError::ContactAlreadyExists(name.to_string()));
        }

        self.contacts.contacts.insert(
            name.to_string(),
            Contact {
                name: name.to_string(),
                email: email.map(String::from),
                key_fingerprints: Vec::new(),
                notes: notes.map(String::from),
                created_at: Utc::now(),
            },
        );
        self.save_contacts()?;
        Ok(())
    }

    /// Associate a key fingerprint with a contact.
    pub fn associate_key_with_contact(
        &mut self,
        contact_name: &str,
        fingerprint: &str,
    ) -> HbResult<()> {
        let contact = self
            .contacts
            .contacts
            .get_mut(contact_name)
            .ok_or_else(|| HbError::ContactNotFound(contact_name.to_string()))?;

        if !contact.key_fingerprints.contains(&fingerprint.to_string()) {
            contact.key_fingerprints.push(fingerprint.to_string());
        }
        self.save_contacts()?;
        Ok(())
    }

    /// Get a contact by name.
    pub fn get_contact(&self, name: &str) -> Option<&Contact> {
        self.contacts.contacts.get(name)
    }

    /// List all contacts.
    pub fn list_contacts(&self) -> Vec<&Contact> {
        self.contacts.contacts.values().collect()
    }

    /// Remove a contact.
    pub fn remove_contact(&mut self, name: &str) -> HbResult<()> {
        if self.contacts.contacts.remove(name).is_none() {
            return Err(HbError::ContactNotFound(name.to_string()));
        }
        self.save_contacts()?;
        Ok(())
    }

    /// Update a contact's email and/or notes.
    ///
    /// Only fields that are `Some` are updated; `None` leaves the existing
    /// value unchanged.
    pub fn update_contact(
        &mut self,
        name: &str,
        email: Option<Option<&str>>,
        notes: Option<Option<&str>>,
    ) -> HbResult<()> {
        let contact = self
            .contacts
            .contacts
            .get_mut(name)
            .ok_or_else(|| HbError::ContactNotFound(name.to_string()))?;
        if let Some(new_email) = email {
            contact.email = new_email.map(String::from);
        }
        if let Some(new_notes) = notes {
            contact.notes = new_notes.map(String::from);
        }
        self.save_contacts()?;
        Ok(())
    }

    /// Resolve a contact name to their public key fingerprints.
    pub fn resolve_recipient(&self, name_or_fp: &str) -> Vec<String> {
        // Try as a contact name first
        if let Some(contact) = self.contacts.contacts.get(name_or_fp) {
            return contact.key_fingerprints.clone();
        }
        // Try as a fingerprint prefix
        let matches: Vec<String> = self
            .index
            .keys
            .keys()
            .filter(|fp| fp.starts_with(name_or_fp))
            .cloned()
            .collect();
        matches
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_keystore() -> (tempfile::TempDir, KeyStore) {
        let dir = tempfile::tempdir().unwrap();
        let ks = KeyStore::open(dir.path().to_path_buf()).unwrap();
        (dir, ks)
    }

    #[test]
    fn test_store_and_load_keys() {
        let (_dir, mut ks) = temp_keystore();
        let fake_key = b"this is a fake private key for testing purposes";
        let passphrase = b"secure_passphrase";
        let fp = "abc123def456";

        ks.store_private_key(fp, fake_key, passphrase, KeyAlgorithm::Ed25519, "Test Key")
            .unwrap();
        ks.store_public_key(fp, b"public key data", KeyAlgorithm::Ed25519, "Test Key")
            .unwrap();

        let loaded = ks.load_private_key(fp, passphrase).unwrap();
        assert_eq!(loaded, fake_key);

        let pub_loaded = ks.load_public_key(fp).unwrap();
        assert_eq!(pub_loaded, b"public key data");
    }

    #[test]
    fn test_wrong_passphrase() {
        let (_dir, mut ks) = temp_keystore();
        let fp = "testkey1";
        ks.store_private_key(fp, b"secret", b"correct", KeyAlgorithm::Rsa2048, "Test")
            .unwrap();

        let result = ks.load_private_key(fp, b"wrong");
        assert!(matches!(result, Err(HbError::InvalidPassphrase)));
    }

    #[test]
    fn test_contacts() {
        let (_dir, mut ks) = temp_keystore();
        ks.add_contact("Alice", Some("alice@example.com"), None)
            .unwrap();
        ks.add_contact("Bob", None, Some("Bob's note")).unwrap();

        assert_eq!(ks.list_contacts().len(), 2);
        assert!(ks.get_contact("Alice").is_some());

        ks.associate_key_with_contact("Alice", "fingerprint123")
            .unwrap();
        let alice = ks.get_contact("Alice").unwrap();
        assert_eq!(alice.key_fingerprints, vec!["fingerprint123"]);

        ks.remove_contact("Bob").unwrap();
        assert_eq!(ks.list_contacts().len(), 1);
    }

    #[test]
    fn test_key_format_detection() {
        assert_eq!(
            detect_key_format(b"-----BEGIN PRIVATE KEY-----\n..."),
            KeyFormat::Pkcs8Pem
        );
        assert_eq!(
            detect_key_format(b"-----BEGIN RSA PRIVATE KEY-----\n..."),
            KeyFormat::Pkcs1Pem
        );
        assert_eq!(
            detect_key_format(b"-----BEGIN PGP PUBLIC KEY BLOCK-----\n..."),
            KeyFormat::OpenPgpArmor
        );
        assert_eq!(
            detect_key_format(b"ssh-ed25519 AAAA..."),
            KeyFormat::OpenSsh
        );
        assert_eq!(detect_key_format(&[0x30, 0x82]), KeyFormat::Der);
    }
}
