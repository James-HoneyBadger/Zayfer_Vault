//! Keystore backup and recovery functionality.
//!
//! Provides encrypted backup of the entire keystore for disaster recovery.
//! Backups are encrypted with a strong passphrase and include all keys,
//! contacts, and keyring metadata.

use std::fs;
use std::io::{Read, Write};
use std::path::Path;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::error::{HbError, HbResult};
use crate::keystore::KeyStore;
use crate::kdf::{self, KdfParams};
use crate::aes_gcm;

/// Backup metadata and manifest.
#[derive(Debug, Serialize, Deserialize)]
pub struct BackupManifest {
    /// Backup creation timestamp
    pub created_at: DateTime<Utc>,
    /// Number of private keys in backup
    pub private_key_count: usize,
    /// Number of public keys in backup
    pub public_key_count: usize,
    /// Number of contacts in backup
    pub contact_count: usize,
    /// Backup format version
    pub version: u8,
    /// Optional user-provided label
    pub label: Option<String>,
    /// SHA256 hash of plaintext backup data for integrity verification
    pub integrity_hash: String,
}

/// Encrypted keystore backup.
///
/// Format:
/// ```text
/// [8B] Magic: "HBZFBKUP"
/// [1B] Version: 0x01
/// [1B] KDF algorithm ID
/// [12B] KDF parameters
/// [16B] Salt
/// [12B] Nonce
/// [...] AES-256-GCM encrypted (manifest + all keystore files)
/// ```
const BACKUP_MAGIC: &[u8] = b"HBZFBKUP";
const BACKUP_VERSION: u8 = 0x01;

impl KeyStore {
    /// Create an encrypted backup of the entire keystore.
    ///
    /// The backup includes:
    /// - All private keys (already encrypted)
    /// - All public keys
    /// - Keyring index (keyring.json)
    /// - Contacts (contacts.json)
    /// - Config file (config.toml)
    ///
    /// The entire bundle is encrypted with the provided passphrase using AES-256-GCM.
    pub fn create_backup(&self, output_path: &Path, passphrase: &[u8], label: Option<String>) -> HbResult<()> {
        // Collect all files to backup
        let mut backup_data: Vec<(String, Vec<u8>)> = Vec::new();

        // Read keyring index
        let keyring_path = self.base_path().join("keyring.json");
        if keyring_path.exists() {
            backup_data.push(("keyring.json".into(), fs::read(&keyring_path)?));
        }

        // Read contacts
        let contacts_path = self.base_path().join("contacts.json");
        if contacts_path.exists() {
            backup_data.push(("contacts.json".into(), fs::read(&contacts_path)?));
        }

        // Read config
        let config_path = self.base_path().join("config.toml");
        if config_path.exists() {
            backup_data.push(("config.toml".into(), fs::read(&config_path)?));
        }

        // Read all private keys
        let private_keys_dir = self.base_path().join("keys/private");
        let mut private_count = 0;
        if private_keys_dir.exists() {
            for entry in fs::read_dir(&private_keys_dir)? {
                let entry = entry?;
                let path = entry.path();
                if path.is_file() {
                    let filename = format!("keys/private/{}", entry.file_name().to_string_lossy());
                    backup_data.push((filename, fs::read(&path)?));
                    private_count += 1;
                }
            }
        }

        // Read all public keys
        let public_keys_dir = self.base_path().join("keys/public");
        let mut public_count = 0;
        if public_keys_dir.exists() {
            for entry in fs::read_dir(&public_keys_dir)? {
                let entry = entry?;
                let path = entry.path();
                if path.is_file() {
                    let filename = format!("keys/public/{}", entry.file_name().to_string_lossy());
                    backup_data.push((filename, fs::read(&path)?));
                    public_count += 1;
                }
            }
        }

        // Prepare serialized files payload
        let files_data = serde_json::to_vec(&backup_data)?;

        // Create manifest
        let manifest = BackupManifest {
            created_at: Utc::now(),
            private_key_count: private_count,
            public_key_count: public_count,
            contact_count: self.list_contacts().len(),
            version: BACKUP_VERSION,
            label,
            integrity_hash: hex::encode(Sha256::digest(&files_data)),
        };

        // Serialize all data
        let manifest_json = serde_json::to_vec(&manifest)?;
        let mut plaintext = Vec::new();
        plaintext.extend_from_slice(&(manifest_json.len() as u32).to_le_bytes());
        plaintext.extend_from_slice(&manifest_json);
        plaintext.extend_from_slice(&files_data);

        // Derive encryption key
        let kdf_params = KdfParams::default();
        let salt = kdf::generate_salt(16);
        let enc_key = kdf::derive_key(passphrase, &salt, &kdf_params)?;

        // Encrypt the backup
        let (nonce, ciphertext) = aes_gcm::encrypt(&enc_key, &plaintext, b"hbzf-backup")?;

        // Build backup file
        let mut output = Vec::new();
        output.extend_from_slice(BACKUP_MAGIC);
        output.push(BACKUP_VERSION);
        output.push(kdf_params.algorithm().id());
        
        // Encode KDF params (same as keystore private key envelope)
        match &kdf_params {
            KdfParams::Argon2id(p) => {
                output.extend_from_slice(&p.m_cost.to_le_bytes());
                output.extend_from_slice(&p.t_cost.to_le_bytes());
                output.extend_from_slice(&p.p_cost.to_le_bytes());
            }
            KdfParams::Scrypt(p) => {
                output.push(p.log_n);
                output.extend_from_slice(&[0u8; 3]); // padding
                output.extend_from_slice(&p.r.to_le_bytes());
                output.extend_from_slice(&p.p.to_le_bytes());
            }
        }
        
        output.extend_from_slice(&salt);
        output.extend_from_slice(&nonce);
        output.extend_from_slice(&ciphertext);

        // Write backup file
        let mut file = fs::File::create(output_path)
            .map_err(|e| HbError::Io(format!("Failed to create backup file: {}", e)))?;
        file.write_all(&output)
            .map_err(|e| HbError::Io(format!("Failed to write backup file: {}", e)))?;

        // Set restrictive permissions on Unix
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let perms = fs::Permissions::from_mode(0o600);
            let _ = fs::set_permissions(output_path, perms);
        }

        Ok(())
    }

    /// Restore keystore from an encrypted backup.
    ///
    /// This will decrypt the backup and restore all keys, contacts, and configuration
    /// to the keystore's base path. Existing files will be overwritten.
    pub fn restore_backup(backup_path: &Path, passphrase: &[u8], target_keystore: &Path) -> HbResult<BackupManifest> {
        // Read backup file
        let mut file = fs::File::open(backup_path)
            .map_err(|e| HbError::Io(format!("Failed to open backup file: {}", e)))?;
        
        let mut contents = Vec::new();
        file.read_to_end(&mut contents)
            .map_err(|e| HbError::Io(format!("Failed to read backup file: {}", e)))?;

        // Verify magic
        if contents.len() < 38 {
            return Err(HbError::InvalidFormat("Backup file too small".into()));
        }
        if &contents[0..8] != BACKUP_MAGIC {
            return Err(HbError::InvalidFormat("Not a valid HBZF backup file".into()));
        }

        let version = contents[8];
        if version != BACKUP_VERSION {
            return Err(HbError::UnsupportedVersion(version));
        }

        // Parse KDF params
        let kdf_algo = contents[9];
        let kdf_params = if kdf_algo == 1 {
            // Argon2id
            let m_cost = u32::from_le_bytes([contents[10], contents[11], contents[12], contents[13]]);
            let t_cost = u32::from_le_bytes([contents[14], contents[15], contents[16], contents[17]]);
            let p_cost = u32::from_le_bytes([contents[18], contents[19], contents[20], contents[21]]);
            KdfParams::argon2id(m_cost, t_cost, p_cost)
        } else if kdf_algo == 2 {
            // scrypt
            let log_n = contents[10];
            let r = u32::from_le_bytes([contents[14], contents[15], contents[16], contents[17]]);
            let p = u32::from_le_bytes([contents[18], contents[19], contents[20], contents[21]]);
            KdfParams::scrypt(log_n, r, p)
        } else {
            return Err(HbError::UnsupportedAlgorithm(format!("KDF algorithm {}", kdf_algo)));
        };

        let salt = &contents[22..38];
        let nonce = &contents[38..50];
        let ciphertext = &contents[50..];

        // Derive decryption key
        let dec_key = kdf::derive_key(passphrase, salt, &kdf_params)?;

        // Decrypt
        let plaintext = aes_gcm::decrypt(&dec_key, nonce, ciphertext, b"hbzf-backup")?;

        // Parse manifest
        if plaintext.len() < 4 {
            return Err(HbError::InvalidFormat("Backup data too small".into()));
        }
        let manifest_len = u32::from_le_bytes([plaintext[0], plaintext[1], plaintext[2], plaintext[3]]) as usize;
        if plaintext.len() < 4 + manifest_len {
            return Err(HbError::InvalidFormat("Truncated backup manifest".into()));
        }

        let manifest: BackupManifest = serde_json::from_slice(&plaintext[4..4 + manifest_len])?;
        let files_data: Vec<(String, Vec<u8>)> = serde_json::from_slice(&plaintext[4 + manifest_len..])?;

        // Verify integrity of payload
        let computed_hash = hex::encode(Sha256::digest(&plaintext[4 + manifest_len..]));
        if computed_hash != manifest.integrity_hash {
            return Err(HbError::AuthenticationFailed);
        }

        // Create target directory structure
        fs::create_dir_all(target_keystore)?;
        fs::create_dir_all(target_keystore.join("keys/private"))?;
        fs::create_dir_all(target_keystore.join("keys/public"))?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let perms = fs::Permissions::from_mode(0o700);
            let _ = fs::set_permissions(target_keystore.join("keys/private"), perms);
        }

        // Restore all files
        for (filename, data) in files_data {
            // Sanitize filename to prevent path traversal attacks
            if filename.contains("..")
                || filename.starts_with('/')
                || filename.starts_with('\\')
            {
                return Err(HbError::InvalidFormat(
                    format!("Malicious filename in backup: {filename}"),
                ));
            }

            let file_path = target_keystore.join(&filename);

            // Verify the resolved path is actually inside the target directory
            let canonical_target = fs::canonicalize(target_keystore)?;
            if let Ok(canonical_file) = fs::canonicalize(file_path.parent().unwrap_or(&file_path)) {
                if !canonical_file.starts_with(&canonical_target) {
                    return Err(HbError::InvalidFormat(
                        format!("Path traversal detected in backup: {filename}"),
                    ));
                }
            }

            // Ensure parent directory exists
            if let Some(parent) = file_path.parent() {
                fs::create_dir_all(parent)?;
            }
            
            fs::write(&file_path, &data)?;

            // Set permissions on private keys
            #[cfg(unix)]
            if filename.starts_with("keys/private/") {
                use std::os::unix::fs::PermissionsExt;
                let perms = fs::Permissions::from_mode(0o600);
                let _ = fs::set_permissions(&file_path, perms);
            }
        }

        Ok(manifest)
    }

    /// Verify a backup file without restoring it.
    ///
    /// Returns the backup manifest if the backup is valid and can be decrypted.
    pub fn verify_backup(backup_path: &Path, passphrase: &[u8]) -> HbResult<BackupManifest> {
        use std::env;
        let temp_dir = env::temp_dir().join(format!("hbzf-verify-{}", uuid::Uuid::new_v4()));
        let result = Self::restore_backup(backup_path, passphrase, &temp_dir);
        
        // Clean up temp directory
        let _ = fs::remove_dir_all(&temp_dir);
        
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_backup_restore() {
        // Create a keystore with some data
        let temp_dir = TempDir::new().unwrap();
        let mut ks = KeyStore::open(temp_dir.path().join("original")).unwrap();
        
        ks.store_private_key("fp1", b"key1", b"pass1", crate::keystore::KeyAlgorithm::Ed25519, "Key 1").unwrap();
        ks.store_public_key("fp1", b"pubkey1", crate::keystore::KeyAlgorithm::Ed25519, "Key 1").unwrap();
        ks.add_contact("Alice", Some("alice@example.com"), None).unwrap();

        // Create backup
        let backup_path = temp_dir.path().join("backup.hbzfbkup");
        ks.create_backup(&backup_path, b"backup-passphrase", Some("Test backup".into())).unwrap();

        // Verify backup exists and has correct magic
        let backup_data = fs::read(&backup_path).unwrap();
        assert_eq!(&backup_data[0..8], BACKUP_MAGIC);

        // Restore to new location
        let restore_path = temp_dir.path().join("restored");
        let manifest = KeyStore::restore_backup(&backup_path, b"backup-passphrase", &restore_path).unwrap();

        assert_eq!(manifest.private_key_count, 1);
        assert_eq!(manifest.public_key_count, 1);
        assert_eq!(manifest.contact_count, 1);
        assert_eq!(manifest.label, Some("Test backup".into()));

        // Verify restored keystore
        let restored_ks = KeyStore::open(restore_path).unwrap();
        assert_eq!(restored_ks.list_keys().len(), 1);
        assert_eq!(restored_ks.list_contacts().len(), 1);
    }

    #[test]
    fn test_backup_wrong_passphrase() {
        let temp_dir = TempDir::new().unwrap();
        let ks = KeyStore::open(temp_dir.path().join("original")).unwrap();
        
        let backup_path = temp_dir.path().join("backup.hbzfbkup");
        ks.create_backup(&backup_path, b"correct-pass", None).unwrap();

        let restore_path = temp_dir.path().join("restored");
        let result = KeyStore::restore_backup(&backup_path, b"wrong-pass", &restore_path);
        
        assert!(result.is_err());
    }

    #[test]
    fn test_backup_verify() {
        let temp_dir = TempDir::new().unwrap();
        let mut ks = KeyStore::open(temp_dir.path().join("original")).unwrap();
        ks.add_contact("Bob", None, None).unwrap();
        
        let backup_path = temp_dir.path().join("backup.hbzfbkup");
        ks.create_backup(&backup_path, b"test-pass", Some("Verify test".into())).unwrap();

        let manifest = KeyStore::verify_backup(&backup_path, b"test-pass").unwrap();
        assert_eq!(manifest.contact_count, 1);
        assert_eq!(manifest.label, Some("Verify test".into()));
    }
}
