//! Shared Rust-native service helpers for the platform layer.
//!
//! These helpers are intentionally lightweight and orchestration-focused so
//! higher-level Rust entry points can remain consistent without duplicating
//! keystore, audit, and config logic.

use std::io::Cursor;
use std::path::PathBuf;

use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use serde::{Deserialize, Serialize};

use crate::{
    ed25519, format, kdf, openpgp, rsa, x25519, AppInfo, AppPaths, AuditLogger, AuditOperation,
    BackupManifest, Config, HbError, HbResult, KeyAlgorithm, KeyStore, KeyWrapping,
    SymmetricAlgorithm,
};

/// Summary of current platform state for CLI and server endpoints.
#[derive(Debug, Clone, Serialize)]
pub struct WorkspaceSummary {
    pub brand_name: String,
    pub version: String,
    pub key_count: usize,
    pub contact_count: usize,
    pub audit_count: usize,
    pub app_home: String,
}

impl WorkspaceSummary {
    /// Collect workspace summary values from the default keystore and audit log.
    pub fn collect() -> HbResult<Self> {
        let info = AppInfo::current();
        let paths = AppPaths::current()?;
        let keystore = KeyStore::open_default()?;
        let audit = AuditLogger::default_location()?;

        Ok(Self {
            brand_name: info.brand_name.to_string(),
            version: info.version.to_string(),
            key_count: keystore.list_keys().len(),
            contact_count: keystore.list_contacts().len(),
            audit_count: audit.entry_count()?,
            app_home: paths.app_home.display().to_string(),
        })
    }
}

/// Web/CLI-friendly config snapshot.
#[derive(Debug, Clone, Serialize)]
pub struct ConfigSnapshot {
    pub default_algorithm: String,
    pub kdf_preset: String,
    pub chunk_size: usize,
    pub audit_enabled: bool,
}

impl ConfigSnapshot {
    /// Load the current default configuration snapshot.
    pub fn load() -> HbResult<Self> {
        let config = Config::load_default()?;
        Ok(Self::from(&config))
    }
}

impl From<&Config> for ConfigSnapshot {
    fn from(config: &Config) -> Self {
        Self {
            default_algorithm: format!("{:?}", config.default_symmetric_algorithm),
            kdf_preset: format!("{:?}", config.kdf_preset),
            chunk_size: config.chunk_size,
            audit_enabled: config.enable_audit_log,
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct KeyGenerationSummary {
    pub fingerprint: String,
    pub algorithm: String,
    pub label: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct WebConfigView {
    pub cipher: String,
    pub kdf: String,
    pub chunk_size: usize,
    pub audit_enabled: bool,
    pub dark_mode: bool,
    pub clipboard_auto_clear: u32,
}

#[derive(Debug, Serialize, Deserialize)]
struct TextCipherEnvelope {
    version: u8,
    algorithm: String,
    salt_b64: String,
    nonce_b64: String,
    ciphertext_b64: String,
}

fn audit_log_safe(operation: AuditOperation) {
    if let Ok(logger) = AuditLogger::default_location() {
        let _ = logger.log(operation, Some("source=rust-platform-service".to_string()));
    }
}

fn normalize_cipher_algorithm(algorithm: &str) -> HbResult<SymmetricAlgorithm> {
    let normalized = algorithm.trim().to_lowercase().replace(['-', '/'], "");
    match normalized.as_str() {
        "aes" | "aes256gcm" => Ok(SymmetricAlgorithm::Aes256Gcm),
        "chacha" | "chacha20" | "chacha20poly1305" => Ok(SymmetricAlgorithm::ChaCha20Poly1305),
        _ => Err(HbError::UnsupportedAlgorithm(algorithm.to_string())),
    }
}

fn normalize_key_algorithm(algorithm: &str) -> HbResult<&'static str> {
    let normalized = algorithm.trim().to_lowercase().replace(['-', '/'], "");
    match normalized.as_str() {
        "rsa" | "rsa2048" => Ok("rsa2048"),
        "rsa4096" => Ok("rsa4096"),
        "ed25519" => Ok("ed25519"),
        "x25519" => Ok("x25519"),
        "pgp" | "gpg" => Ok("pgp"),
        _ => Err(HbError::UnsupportedAlgorithm(algorithm.to_string())),
    }
}

fn normalize_sign_algorithm(algorithm: &str) -> HbResult<&'static str> {
    let normalized = algorithm.trim().to_lowercase().replace(['-', '/'], "");
    match normalized.as_str() {
        "ed25519" => Ok("ed25519"),
        "rsa" | "rsa2048" | "rsa4096" => Ok("rsa"),
        "pgp" | "gpg" => Ok("pgp"),
        _ => Err(HbError::UnsupportedAlgorithm(algorithm.to_string())),
    }
}

fn validate_managed_path(raw_path: &str, field_name: &str) -> HbResult<PathBuf> {
    AppPaths::current()?.resolve_user_path(raw_path, field_name)
}

pub fn load_web_config() -> HbResult<WebConfigView> {
    let config = Config::load_default()?;
    Ok(WebConfigView {
        cipher: config.get("cipher")?,
        kdf: config.get("kdf")?,
        chunk_size: config.chunk_size,
        audit_enabled: config.enable_audit_log,
        dark_mode: config.gui.dark_mode,
        clipboard_auto_clear: config.gui.clipboard_auto_clear,
    })
}

pub fn update_web_config(key: &str, value: &str) -> HbResult<String> {
    let mut config = Config::load_default()?;
    config.set(key, value)?;
    config.save_default()?;
    config.get(key)
}

pub fn encrypt_file_payload(
    input_name: Option<&str>,
    contents: &[u8],
    passphrase: &str,
    algorithm: &str,
) -> HbResult<(String, Vec<u8>)> {
    let algorithm = normalize_cipher_algorithm(algorithm)?;
    let kdf_params = kdf::KdfParams::default();
    let salt = kdf::generate_salt(16);
    let key = kdf::derive_key(passphrase.as_bytes(), &salt, &kdf_params)?;

    let params = format::EncryptParams {
        algorithm,
        wrapping: KeyWrapping::Password,
        symmetric_key: key,
        kdf_params: Some(kdf_params),
        kdf_salt: Some(salt),
        wrapped_key: None,
        ephemeral_public: None,
        chunk_size: None,
        compress: contents.len() > 4096,
    };

    let mut reader = Cursor::new(contents);
    let mut output = Vec::new();
    format::encrypt_stream(
        &mut reader,
        &mut output,
        &params,
        contents.len() as u64,
        None,
    )?;

    let output_name = format!("{}.hbzf", input_name.unwrap_or("encrypted"));
    audit_log_safe(AuditOperation::FileEncrypted {
        algorithm: format!("{:?}", algorithm),
        filename: input_name.map(str::to_string),
        size_bytes: Some(contents.len() as u64),
    });

    Ok((output_name, output))
}

pub fn decrypt_file_payload(
    input_name: Option<&str>,
    contents: &[u8],
    passphrase: &str,
) -> HbResult<(String, Vec<u8>)> {
    let mut reader = Cursor::new(contents);
    let header = format::read_header(&mut reader)?;

    let symmetric_key = match header.wrapping {
        KeyWrapping::Password => {
            let salt = header
                .kdf_salt
                .as_ref()
                .ok_or_else(|| HbError::InvalidFormat("Missing KDF salt in file".into()))?;
            let params = header
                .kdf_params
                .as_ref()
                .ok_or_else(|| HbError::InvalidFormat("Missing KDF params in file".into()))?;
            kdf::derive_key(passphrase.as_bytes(), salt, params)?
        }
        _ => {
            return Err(HbError::UnsupportedAlgorithm(
                "Only password-wrapped file uploads are supported in the native web runtime".into(),
            ));
        }
    };

    let mut output = Vec::new();
    format::decrypt_stream(&mut reader, &mut output, &header, &symmetric_key, None)?;

    let output_name = input_name
        .and_then(|name| name.strip_suffix(".hbzf").map(str::to_string))
        .unwrap_or_else(|| "decrypted".to_string());

    audit_log_safe(AuditOperation::FileDecrypted {
        algorithm: format!("{:?}", header.algorithm),
        filename: input_name.map(str::to_string),
        size_bytes: Some(output.len() as u64),
    });

    Ok((output_name, output))
}

pub fn create_backup_archive(
    output_path: &str,
    passphrase: &str,
    label: Option<&str>,
) -> HbResult<BackupManifest> {
    let path = validate_managed_path(output_path, "output_path")?;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let keystore = KeyStore::open_default()?;
    keystore.create_backup(&path, passphrase.as_bytes(), label.map(str::to_string))?;
    KeyStore::verify_backup(&path, passphrase.as_bytes())
}

pub fn verify_backup_archive(backup_path: &str, passphrase: &str) -> HbResult<BackupManifest> {
    let path = validate_managed_path(backup_path, "backup_path")?;
    KeyStore::verify_backup(&path, passphrase.as_bytes())
}

pub fn restore_backup_archive(backup_path: &str, passphrase: &str) -> HbResult<BackupManifest> {
    let path = validate_managed_path(backup_path, "backup_path")?;
    let app_home = AppPaths::current()?.app_home;
    KeyStore::restore_backup(&path, passphrase.as_bytes(), &app_home)
}

pub fn generate_and_store_key(
    keystore: &mut KeyStore,
    algorithm: &str,
    label: &str,
    passphrase: &str,
    user_id: Option<&str>,
) -> HbResult<KeyGenerationSummary> {
    let algorithm = normalize_key_algorithm(algorithm)?;

    let (fingerprint, key_algorithm, private_bytes, public_bytes) = match algorithm {
        "rsa2048" => {
            let kp = rsa::generate_keypair(rsa::RsaKeySize::Rsa2048)?;
            let fp = rsa::fingerprint(&kp.public_key)?;
            let private = rsa::export_private_key_pem(&kp.private_key)?;
            let public = rsa::export_public_key_pem(&kp.public_key)?;
            (
                fp,
                KeyAlgorithm::Rsa2048,
                private.into_bytes(),
                public.into_bytes(),
            )
        }
        "rsa4096" => {
            let kp = rsa::generate_keypair(rsa::RsaKeySize::Rsa4096)?;
            let fp = rsa::fingerprint(&kp.public_key)?;
            let private = rsa::export_private_key_pem(&kp.private_key)?;
            let public = rsa::export_public_key_pem(&kp.public_key)?;
            (
                fp,
                KeyAlgorithm::Rsa4096,
                private.into_bytes(),
                public.into_bytes(),
            )
        }
        "ed25519" => {
            let kp = ed25519::generate_keypair();
            let fp = ed25519::fingerprint(&kp.verifying_key);
            let private = ed25519::export_signing_key_pem(&kp.signing_key)?;
            let public = ed25519::export_verifying_key_pem(&kp.verifying_key)?;
            (
                fp,
                KeyAlgorithm::Ed25519,
                private.into_bytes(),
                public.into_bytes(),
            )
        }
        "x25519" => {
            let kp = x25519::generate_keypair();
            let fp = x25519::fingerprint(&kp.public_key);
            let private = x25519::export_secret_key_raw(&kp.secret_key);
            let public = x25519::export_public_key_raw(&kp.public_key);
            (fp, KeyAlgorithm::X25519, private, public)
        }
        "pgp" => {
            let cert = openpgp::generate_cert(user_id.unwrap_or(label))?;
            let fp = openpgp::cert_fingerprint(&cert);
            let private = openpgp::export_secret_key(&cert)?;
            let public = openpgp::export_public_key(&cert)?;
            (
                fp,
                KeyAlgorithm::Pgp,
                private.into_bytes(),
                public.into_bytes(),
            )
        }
        _ => unreachable!(),
    };

    keystore.store_private_key(
        &fingerprint,
        &private_bytes,
        passphrase.as_bytes(),
        key_algorithm.clone(),
        label,
    )?;
    keystore.store_public_key(&fingerprint, &public_bytes, key_algorithm, label)?;

    audit_log_safe(AuditOperation::KeyGenerated {
        algorithm: algorithm.to_string(),
        fingerprint: fingerprint.clone(),
    });

    Ok(KeyGenerationSummary {
        fingerprint,
        algorithm: algorithm.to_string(),
        label: label.to_string(),
    })
}

pub fn encrypt_text_payload(
    plaintext: &str,
    passphrase: &str,
    algorithm: &str,
) -> HbResult<String> {
    let algorithm = normalize_cipher_algorithm(algorithm)?;
    let derived = kdf::derive_key_fresh(passphrase.as_bytes(), &kdf::KdfParams::default())?;
    let (nonce, ciphertext) = format::encrypt_bytes(plaintext.as_bytes(), &derived.key, algorithm)?;

    let envelope = TextCipherEnvelope {
        version: 1,
        algorithm: match algorithm {
            SymmetricAlgorithm::Aes256Gcm => "aes".to_string(),
            SymmetricAlgorithm::ChaCha20Poly1305 => "chacha".to_string(),
        },
        salt_b64: BASE64.encode(&derived.salt),
        nonce_b64: BASE64.encode(&nonce),
        ciphertext_b64: BASE64.encode(&ciphertext),
    };

    Ok(BASE64.encode(serde_json::to_vec(&envelope)?))
}

pub fn decrypt_text_payload(ciphertext_b64: &str, passphrase: &str) -> HbResult<String> {
    let encoded = BASE64
        .decode(ciphertext_b64.as_bytes())
        .map_err(|e| HbError::InvalidFormat(format!("Invalid base64 payload: {e}")))?;
    let envelope: TextCipherEnvelope = serde_json::from_slice(&encoded)?;
    let algorithm = normalize_cipher_algorithm(&envelope.algorithm)?;
    let salt = BASE64
        .decode(envelope.salt_b64.as_bytes())
        .map_err(|e| HbError::InvalidFormat(format!("Invalid salt encoding: {e}")))?;
    let nonce = BASE64
        .decode(envelope.nonce_b64.as_bytes())
        .map_err(|e| HbError::InvalidFormat(format!("Invalid nonce encoding: {e}")))?;
    let ciphertext = BASE64
        .decode(envelope.ciphertext_b64.as_bytes())
        .map_err(|e| HbError::InvalidFormat(format!("Invalid ciphertext encoding: {e}")))?;

    let key = kdf::derive_key(passphrase.as_bytes(), &salt, &kdf::KdfParams::default())?;
    let plaintext = format::decrypt_bytes(&nonce, &ciphertext, &key, algorithm)?;
    String::from_utf8(plaintext)
        .map_err(|e| HbError::InvalidFormat(format!("Invalid UTF-8 plaintext: {e}")))
}

pub fn sign_message_payload(
    keystore: &KeyStore,
    message_b64: &str,
    fingerprint: &str,
    passphrase: &str,
    algorithm: &str,
) -> HbResult<String> {
    let algorithm = normalize_sign_algorithm(algorithm)?;
    let message = BASE64
        .decode(message_b64.as_bytes())
        .map_err(|e| HbError::InvalidFormat(format!("Invalid base64 message: {e}")))?;

    let signature = match algorithm {
        "ed25519" => {
            let private_data = keystore.load_private_key(fingerprint, passphrase.as_bytes())?;
            let private_pem = String::from_utf8(private_data)
                .map_err(|e| HbError::InvalidKeyFormat(format!("UTF-8 private key: {e}")))?;
            let signing_key = ed25519::import_signing_key_pem(&private_pem)?;
            ed25519::sign(&signing_key, &message)
        }
        "rsa" => {
            let private_data = keystore.load_private_key(fingerprint, passphrase.as_bytes())?;
            let private_pem = String::from_utf8(private_data)
                .map_err(|e| HbError::InvalidKeyFormat(format!("UTF-8 private key: {e}")))?;
            let private_key = rsa::import_private_key_pem(&private_pem)?;
            rsa::sign(&private_key, &message)?
        }
        "pgp" => {
            let private_data = keystore.load_private_key(fingerprint, passphrase.as_bytes())?;
            let private_cert = String::from_utf8(private_data)
                .map_err(|e| HbError::InvalidKeyFormat(format!("UTF-8 private cert: {e}")))?;
            let cert = openpgp::import_cert(&private_cert)?;
            openpgp::sign_message(&message, &cert)?
        }
        _ => unreachable!(),
    };

    audit_log_safe(AuditOperation::DataSigned {
        algorithm: algorithm.to_string(),
        fingerprint: fingerprint.to_string(),
    });

    Ok(BASE64.encode(signature))
}

pub fn verify_message_payload(
    keystore: &KeyStore,
    message_b64: &str,
    signature_b64: &str,
    fingerprint: &str,
    algorithm: &str,
) -> HbResult<bool> {
    let algorithm = normalize_sign_algorithm(algorithm)?;
    let message = BASE64
        .decode(message_b64.as_bytes())
        .map_err(|e| HbError::InvalidFormat(format!("Invalid base64 message: {e}")))?;
    let signature = BASE64
        .decode(signature_b64.as_bytes())
        .map_err(|e| HbError::InvalidFormat(format!("Invalid base64 signature: {e}")))?;

    let valid = match algorithm {
        "ed25519" => {
            let public_data = keystore.load_public_key(fingerprint)?;
            let public_pem = String::from_utf8(public_data)
                .map_err(|e| HbError::InvalidKeyFormat(format!("UTF-8 public key: {e}")))?;
            let verifying_key = ed25519::import_verifying_key_pem(&public_pem)?;
            ed25519::verify(&verifying_key, &message, &signature)?
        }
        "rsa" => {
            let public_data = keystore.load_public_key(fingerprint)?;
            let public_pem = String::from_utf8(public_data)
                .map_err(|e| HbError::InvalidKeyFormat(format!("UTF-8 public key: {e}")))?;
            let public_key = rsa::import_public_key_pem(&public_pem)?;
            rsa::verify(&public_key, &message, &signature)?
        }
        "pgp" => {
            let public_data = keystore.load_public_key(fingerprint)?;
            let public_cert = String::from_utf8(public_data)
                .map_err(|e| HbError::InvalidKeyFormat(format!("UTF-8 public cert: {e}")))?;
            let cert = openpgp::import_cert(&public_cert)?;
            let (_, is_valid) = openpgp::verify_message(&signature, &[cert])?;
            is_valid
        }
        _ => unreachable!(),
    };

    audit_log_safe(AuditOperation::SignatureVerified {
        algorithm: algorithm.to_string(),
        fingerprint: fingerprint.to_string(),
        valid,
    });

    Ok(valid)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_snapshot_loads() {
        let snap = ConfigSnapshot::load().unwrap();
        assert!(!snap.default_algorithm.is_empty());
        assert!(snap.chunk_size >= 4096);
    }

    #[test]
    fn text_payload_roundtrip() {
        let ciphertext = encrypt_text_payload("hello from rust", "secret", "aes").unwrap();
        let plaintext = decrypt_text_payload(&ciphertext, "secret").unwrap();
        assert_eq!(plaintext, "hello from rust");
    }

    #[test]
    fn file_payload_roundtrip() {
        let (name, ciphertext) =
            encrypt_file_payload(Some("note.txt"), b"hello file", "secret", "aes").unwrap();
        assert_eq!(name, "note.txt.hbzf");
        let (out_name, plaintext) =
            decrypt_file_payload(Some(&name), &ciphertext, "secret").unwrap();
        assert_eq!(out_name, "note.txt");
        assert_eq!(plaintext, b"hello file");
    }

    #[test]
    fn web_config_loads() {
        let config = load_web_config().unwrap();
        assert!(!config.cipher.is_empty());
        assert!(!config.kdf.is_empty());
        assert!(config.clipboard_auto_clear <= 600);
    }
}
