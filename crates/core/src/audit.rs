//! Audit logging for cryptographic operations.
//!
//! Provides append-only logging of key operations for security auditing and
//! accountability. The audit log is stored at `~/.hb_zayfer/audit.log` with
//! each entry containing timestamp, operation type, and relevant metadata.
//!
//! Log entries are timestamped and include a chain hash for integrity verification.

use std::fs::{self, File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};

use chrono::{DateTime, Utc};
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::error::{HbError, HbResult};

type HmacSha256 = Hmac<Sha256>;

/// Types of operations that can be audited.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AuditOperation {
    KeyGenerated { algorithm: String, fingerprint: String },
    KeyImported { algorithm: String, fingerprint: String },
    KeyExported { fingerprint: String },
    KeyDeleted { fingerprint: String },
    FileEncrypted { algorithm: String, filename: Option<String>, size_bytes: Option<u64> },
    FileDecrypted { algorithm: String, filename: Option<String>, size_bytes: Option<u64> },
    DataSigned { algorithm: String, fingerprint: String },
    SignatureVerified { algorithm: String, fingerprint: String, valid: bool },
    ContactAdded { name: String },
    ContactDeleted { name: String },
    BackupCreated { key_count: usize },
    BackupRestored { key_count: usize },
    ConfigModified { setting: String },
}

/// A single audit log entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEntry {
    /// Timestamp of the operation
    pub timestamp: DateTime<Utc>,
    /// Type of operation
    pub operation: AuditOperation,
    /// Hash of previous entry for chain integrity
    pub prev_hash: Option<String>,
    /// Hash of this entry
    pub entry_hash: String,
    /// Optional user-provided note
    pub note: Option<String>,
    /// HMAC-SHA256 of the entry (set when logger has an HMAC key)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hmac: Option<String>,
}

impl AuditEntry {
    /// Create a new audit entry.
    pub fn new(operation: AuditOperation, prev_hash: Option<String>, note: Option<String>) -> Self {
        let timestamp = Utc::now();
        let mut entry = Self {
            timestamp,
            operation,
            prev_hash,
            entry_hash: String::new(),
            note,
            hmac: None,
        };
        entry.entry_hash = entry.compute_hash();
        entry
    }

    /// Create a new audit entry and compute its HMAC with the given key.
    pub fn new_with_hmac(
        operation: AuditOperation,
        prev_hash: Option<String>,
        note: Option<String>,
        hmac_key: &[u8],
    ) -> Self {
        let mut entry = Self::new(operation, prev_hash, note);
        entry.hmac = Some(entry.compute_hmac(hmac_key));
        entry
    }

    /// Compute the hash of this entry (excluding the entry_hash field itself).
    fn compute_hash(&self) -> String {
        let mut hasher = Sha256::new();
        hasher.update(self.timestamp.to_rfc3339().as_bytes());
        hasher.update(serde_json::to_string(&self.operation).unwrap_or_default().as_bytes());
        if let Some(prev) = &self.prev_hash {
            hasher.update(prev.as_bytes());
        }
        if let Some(note) = &self.note {
            hasher.update(note.as_bytes());
        }
        hex::encode(hasher.finalize())
    }

    /// Verify the integrity of this entry.
    pub fn verify(&self) -> bool {
        self.entry_hash == self.compute_hash()
    }

    /// Compute the HMAC-SHA256 of this entry using an external key.
    fn compute_hmac(&self, key: &[u8]) -> String {
        let mut mac = HmacSha256::new_from_slice(key)
            .expect("HMAC accepts any key length");
        mac.update(self.timestamp.to_rfc3339().as_bytes());
        mac.update(serde_json::to_string(&self.operation).unwrap_or_default().as_bytes());
        if let Some(prev) = &self.prev_hash {
            mac.update(prev.as_bytes());
        }
        if let Some(note) = &self.note {
            mac.update(note.as_bytes());
        }
        mac.update(self.entry_hash.as_bytes());
        hex::encode(mac.finalize().into_bytes())
    }

    /// Verify the HMAC of this entry against the given key.
    /// Returns `None` if the entry has no HMAC, `Some(true/false)` otherwise.
    pub fn verify_hmac(&self, key: &[u8]) -> Option<bool> {
        self.hmac.as_ref().map(|stored| {
            // Recompute the HMAC and use the hmac crate's constant-time
            // verify_slice to prevent timing side-channel attacks.
            let mut mac = HmacSha256::new_from_slice(key)
                .expect("HMAC accepts any key length");
            mac.update(self.timestamp.to_rfc3339().as_bytes());
            mac.update(serde_json::to_string(&self.operation).unwrap_or_default().as_bytes());
            if let Some(prev) = &self.prev_hash {
                mac.update(prev.as_bytes());
            }
            if let Some(note) = &self.note {
                mac.update(note.as_bytes());
            }
            mac.update(self.entry_hash.as_bytes());
            let stored_bytes = hex::decode(stored).unwrap_or_default();
            mac.verify_slice(&stored_bytes).is_ok()
        })
    }
}

/// The audit logger manages the append-only log file.
pub struct AuditLogger {
    log_path: PathBuf,
    /// Optional HMAC key for signing entries. When set, each new entry
    /// gets an HMAC-SHA256 tag that can be verified independently of
    /// the hash chain.
    hmac_key: Option<Vec<u8>>,
}

impl AuditLogger {
    /// Create a new audit logger at the specified path.
    pub fn new(log_path: PathBuf) -> Self {
        Self { log_path, hmac_key: None }
    }

    /// Create a new audit logger with an HMAC signing key.
    pub fn with_hmac_key(log_path: PathBuf, hmac_key: Vec<u8>) -> Self {
        Self { log_path, hmac_key: Some(hmac_key) }
    }

    /// Create an audit logger using the default location (~/.hb_zayfer/audit.log).
    pub fn default_location() -> HbResult<Self> {
        let base_dir = dirs::home_dir()
            .ok_or_else(|| HbError::Config("Could not determine home directory".into()))?;
        let log_path = base_dir.join(".hb_zayfer").join("audit.log");
        
        // Ensure the directory exists
        if let Some(parent) = log_path.parent() {
            fs::create_dir_all(parent).map_err(|e| {
                HbError::Io(format!("Failed to create audit log directory: {}", e))
            })?;
        }
        
        Ok(Self::new(log_path))
    }

    /// Get the hash of the last entry in the log.
    fn get_last_hash(&self) -> HbResult<Option<String>> {
        if !self.log_path.exists() {
            return Ok(None);
        }

        let file = File::open(&self.log_path).map_err(|e| {
            HbError::Io(format!("Failed to open audit log: {}", e))
        })?;
        let reader = BufReader::new(file);
        
        let mut last_hash = None;
        for line in reader.lines() {
            let line = line.map_err(|e| {
                HbError::Io(format!("Failed to read audit log: {}", e))
            })?;
            
            if let Ok(entry) = serde_json::from_str::<AuditEntry>(&line) {
                last_hash = Some(entry.entry_hash);
            }
        }
        
        Ok(last_hash)
    }

    /// Log an operation to the audit log.
    pub fn log(&self, operation: AuditOperation, note: Option<String>) -> HbResult<()> {
        let prev_hash = self.get_last_hash()?;
        let entry = if let Some(key) = &self.hmac_key {
            AuditEntry::new_with_hmac(operation, prev_hash, note, key)
        } else {
            AuditEntry::new(operation, prev_hash, note)
        };
        
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.log_path)
            .map_err(|e| HbError::Io(format!("Failed to open audit log: {}", e)))?;
        
        // Set restrictive permissions on Unix
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = file.metadata()
                .map_err(|e| HbError::Io(format!("Failed to get audit log metadata: {}", e)))?
                .permissions();
            perms.set_mode(0o600);
            std::fs::set_permissions(&self.log_path, perms)
                .map_err(|e| HbError::Io(format!("Failed to set audit log permissions: {}", e)))?;
        }
        
        // Write entry as JSON line
        let json = serde_json::to_string(&entry)
            .map_err(|e| HbError::Serialization(format!("Failed to serialize audit entry: {}", e)))?;
        writeln!(file, "{}", json)
            .map_err(|e| HbError::Io(format!("Failed to write audit log: {}", e)))?;
        
        Ok(())
    }

    /// Read all entries from the audit log.
    pub fn read_entries(&self) -> HbResult<Vec<AuditEntry>> {
        if !self.log_path.exists() {
            return Ok(Vec::new());
        }

        let file = File::open(&self.log_path).map_err(|e| {
            HbError::Io(format!("Failed to open audit log: {}", e))
        })?;
        let reader = BufReader::new(file);
        
        let mut entries = Vec::new();
        for line in reader.lines() {
            let line = line.map_err(|e| {
                HbError::Io(format!("Failed to read audit log: {}", e))
            })?;
            
            let entry: AuditEntry = serde_json::from_str(&line)
                .map_err(|e| HbError::Serialization(format!("Failed to parse audit entry: {}", e)))?;
            
            entries.push(entry);
        }
        
        Ok(entries)
    }

    /// Verify the integrity of the entire audit log chain.
    pub fn verify_integrity(&self) -> HbResult<bool> {
        let entries = self.read_entries()?;
        
        if entries.is_empty() {
            return Ok(true);
        }
        
        // Verify first entry
        if !entries[0].verify() {
            return Ok(false);
        }
        if entries[0].prev_hash.is_some() {
            return Ok(false); // First entry should have no previous hash
        }
        
        // Verify chain
        for i in 1..entries.len() {
            if !entries[i].verify() {
                return Ok(false);
            }
            if entries[i].prev_hash.as_ref() != Some(&entries[i - 1].entry_hash) {
                return Ok(false);
            }
        }
        
        Ok(true)
    }

    /// Verify the HMAC tags of all entries that have them.
    ///
    /// Returns `Ok(true)` if every HMAC-tagged entry verifies correctly
    /// (entries without HMAC tags are skipped). Returns the index of the
    /// first failing entry as `Err` if verification fails.
    pub fn verify_hmac_integrity(&self, hmac_key: &[u8]) -> HbResult<Result<(), usize>> {
        let entries = self.read_entries()?;
        for (i, entry) in entries.iter().enumerate() {
            if let Some(valid) = entry.verify_hmac(hmac_key) {
                if !valid {
                    return Ok(Err(i));
                }
            }
        }
        Ok(Ok(()))
    }

    /// Get the total number of entries in the log.
    pub fn entry_count(&self) -> HbResult<usize> {
        Ok(self.read_entries()?.len())
    }

    /// Get the most recent N entries from the log.
    pub fn recent_entries(&self, n: usize) -> HbResult<Vec<AuditEntry>> {
        let mut entries = self.read_entries()?;
        if entries.len() > n {
            entries.drain(0..entries.len() - n);
        }
        Ok(entries)
    }

    /// Export the audit log to a specified path.
    pub fn export(&self, destination: &Path) -> HbResult<()> {
        std::fs::copy(&self.log_path, destination)
            .map_err(|e| HbError::Io(format!("Failed to export audit log: {}", e)))?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_audit_entry_hash() {
        let op = AuditOperation::KeyGenerated {
            algorithm: "RSA-4096".into(),
            fingerprint: "abcd1234".into(),
        };
        let entry = AuditEntry::new(op, None, None);
        assert!(entry.verify());
    }

    #[test]
    fn test_audit_logger() {
        let temp_dir = TempDir::new().unwrap();
        let log_path = temp_dir.path().join("audit.log");
        let logger = AuditLogger::new(log_path);

        // Log some operations
        logger.log(AuditOperation::KeyGenerated {
            algorithm: "RSA-4096".into(),
            fingerprint: "fp1".into(),
        }, None).unwrap();

        logger.log(AuditOperation::FileEncrypted {
            algorithm: "AES-256-GCM".into(),
            filename: Some("test.txt".into()),
            size_bytes: Some(1024),
        }, Some("Test encryption".into())).unwrap();

        // Verify entries
        let entries = logger.read_entries().unwrap();
        assert_eq!(entries.len(), 2);
        assert!(logger.verify_integrity().unwrap());
    }

    #[test]
    fn test_audit_chain_integrity() {
        let temp_dir = TempDir::new().unwrap();
        let log_path = temp_dir.path().join("audit.log");
        let logger = AuditLogger::new(log_path.clone());

        // Create a chain of entries
        for i in 0..5 {
            logger.log(AuditOperation::FileEncrypted {
                algorithm: "AES-256-GCM".into(),
                filename: Some(format!("file{}.txt", i)),
                size_bytes: Some(i * 100),
            }, None).unwrap();
        }

        // Verify chain
        assert!(logger.verify_integrity().unwrap());

        // Tamper with the log
        let mut content = std::fs::read_to_string(&log_path).unwrap();
        content = content.replace("file2", "file9");
        std::fs::write(&log_path, content).unwrap();

        // Verify should fail
        assert!(!logger.verify_integrity().unwrap());
    }

    #[test]
    fn test_recent_entries() {
        let temp_dir = TempDir::new().unwrap();
        let log_path = temp_dir.path().join("audit.log");
        let logger = AuditLogger::new(log_path);

        for i in 0..10 {
            logger.log(AuditOperation::ConfigModified {
                setting: format!("setting{}", i),
            }, None).unwrap();
        }

        let recent = logger.recent_entries(3).unwrap();
        assert_eq!(recent.len(), 3);
    }
}
