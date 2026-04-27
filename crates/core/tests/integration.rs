//! Integration tests for hb_zayfer_core crate.
//!
//! These tests exercise the public API surface end-to-end: KDF, symmetric
//! ciphers, asymmetric key-pairs, signing/verification, the HBZF streaming
//! format, and the on-disk keystore.

use hb_zayfer_core::*;
use hb_zayfer_core::{aes_gcm, chacha20, ed25519, format, kdf, keystore, openpgp, rsa, x25519};
use tempfile::TempDir;

// ==========================================================================
// KDF
// ==========================================================================

#[test]
fn kdf_argon2_produces_correct_length() {
    let salt = kdf::generate_salt(32);
    assert_eq!(salt.len(), 32);
    let params = kdf::KdfParams::Argon2id(kdf::Argon2Params::default());
    let key = kdf::derive_key(b"password", &salt, &params).expect("argon2");
    assert_eq!(key.len(), 32);
}

#[test]
fn kdf_scrypt_produces_correct_length() {
    let salt = kdf::generate_salt(32);
    let params = kdf::KdfParams::Scrypt(kdf::ScryptParams::default());
    let key = kdf::derive_key(b"password", &salt, &params).expect("scrypt");
    assert_eq!(key.len(), 32);
}

#[test]
fn kdf_deterministic() {
    let salt = kdf::generate_salt(32);
    let params = kdf::KdfParams::default();
    let k1 = kdf::derive_key(b"secret", &salt, &params).unwrap();
    let k2 = kdf::derive_key(b"secret", &salt, &params).unwrap();
    assert_eq!(k1, k2);
}

#[test]
fn kdf_different_passwords_differ() {
    let salt = kdf::generate_salt(32);
    let params = kdf::KdfParams::default();
    let k1 = kdf::derive_key(b"alpha", &salt, &params).unwrap();
    let k2 = kdf::derive_key(b"bravo", &salt, &params).unwrap();
    assert_ne!(k1, k2);
}

#[test]
fn kdf_derive_key_fresh() {
    let params = kdf::KdfParams::default();
    let dk = kdf::derive_key_fresh(b"passphrase", &params).unwrap();
    assert_eq!(dk.key.len(), 32);
    assert!(!dk.salt.is_empty());
}

// ==========================================================================
// AES-256-GCM
// ==========================================================================

#[test]
fn aes_encrypt_decrypt_roundtrip() {
    let salt = kdf::generate_salt(32);
    let params = kdf::KdfParams::default();
    let key = kdf::derive_key(b"testpw", &salt, &params).unwrap();
    let plaintext = b"Hello, AES-256-GCM!";

    let (nonce, ct) = aes_gcm::encrypt(&key, plaintext, b"").expect("aes encrypt");
    let pt = aes_gcm::decrypt(&key, &nonce, &ct, b"").expect("aes decrypt");
    assert_eq!(&pt, plaintext);
}

#[test]
fn aes_wrong_key_fails() {
    let p = kdf::KdfParams::default();
    let k1 = kdf::derive_key(b"right", &kdf::generate_salt(32), &p).unwrap();
    let k2 = kdf::derive_key(b"wrong", &kdf::generate_salt(32), &p).unwrap();

    let (nonce, ct) = aes_gcm::encrypt(&k1, b"secret", b"").unwrap();
    assert!(aes_gcm::decrypt(&k2, &nonce, &ct, b"").is_err());
}

#[test]
fn aes_tampered_ciphertext_fails() {
    let key = kdf::derive_key(b"pw", &kdf::generate_salt(32), &kdf::KdfParams::default()).unwrap();
    let (nonce, mut ct) = aes_gcm::encrypt(&key, b"data", b"").unwrap();
    if let Some(b) = ct.last_mut() {
        *b ^= 0xff;
    }
    assert!(aes_gcm::decrypt(&key, &nonce, &ct, b"").is_err());
}

#[test]
fn aes_with_aad() {
    let key = kdf::derive_key(b"pw", &kdf::generate_salt(32), &kdf::KdfParams::default()).unwrap();
    let aad = b"context-data";
    let (nonce, ct) = aes_gcm::encrypt(&key, b"msg", aad).unwrap();

    let pt = aes_gcm::decrypt(&key, &nonce, &ct, aad).unwrap();
    assert_eq!(&pt, b"msg");

    assert!(aes_gcm::decrypt(&key, &nonce, &ct, b"wrong-aad").is_err());
}

// ==========================================================================
// ChaCha20-Poly1305
// ==========================================================================

#[test]
fn chacha_encrypt_decrypt_roundtrip() {
    let key =
        kdf::derive_key(b"test", &kdf::generate_salt(32), &kdf::KdfParams::default()).unwrap();
    let plaintext = b"Hello, ChaCha20-Poly1305!";

    let (nonce, ct) = chacha20::encrypt(&key, plaintext, b"").expect("chacha encrypt");
    let pt = chacha20::decrypt(&key, &nonce, &ct, b"").expect("chacha decrypt");
    assert_eq!(&pt, plaintext);
}

#[test]
fn chacha_wrong_key_fails() {
    let p = kdf::KdfParams::default();
    let k1 = kdf::derive_key(b"one", &kdf::generate_salt(32), &p).unwrap();
    let k2 = kdf::derive_key(b"two", &kdf::generate_salt(32), &p).unwrap();

    let (nonce, ct) = chacha20::encrypt(&k1, b"msg", b"").unwrap();
    assert!(chacha20::decrypt(&k2, &nonce, &ct, b"").is_err());
}

// ==========================================================================
// RSA
// ==========================================================================

#[test]
fn rsa_keygen_and_encrypt_decrypt() {
    let kp = rsa::generate_keypair(rsa::RsaKeySize::Rsa2048).expect("rsa keygen");

    let priv_pem = rsa::export_private_key_pem(&kp.private_key).unwrap();
    let pub_pem = rsa::export_public_key_pem(&kp.public_key).unwrap();
    assert!(priv_pem.contains("BEGIN"));
    assert!(pub_pem.contains("BEGIN"));

    let plaintext = b"RSA roundtrip";
    let ct = rsa::encrypt(&kp.public_key, plaintext).expect("rsa encrypt");
    let pt = rsa::decrypt(&kp.private_key, &ct).expect("rsa decrypt");
    assert_eq!(&pt, plaintext);
}

#[test]
fn rsa_sign_verify() {
    let kp = rsa::generate_keypair(rsa::RsaKeySize::Rsa2048).unwrap();
    let msg = b"Authenticate me";
    let sig = rsa::sign(&kp.private_key, msg).expect("rsa sign");
    assert!(rsa::verify(&kp.public_key, msg, &sig).expect("rsa verify"));
}

#[test]
fn rsa_verify_wrong_message_fails() {
    let kp = rsa::generate_keypair(rsa::RsaKeySize::Rsa2048).unwrap();
    let sig = rsa::sign(&kp.private_key, b"original").unwrap();
    assert!(!rsa::verify(&kp.public_key, b"tampered", &sig).unwrap_or(false));
}

#[test]
fn rsa_fingerprint_consistent() {
    let kp = rsa::generate_keypair(rsa::RsaKeySize::Rsa2048).unwrap();
    let fp1 = rsa::fingerprint(&kp.public_key).unwrap();
    let fp2 = rsa::fingerprint(&kp.public_key).unwrap();
    assert_eq!(fp1, fp2);
    assert!(!fp1.is_empty());
}

#[test]
fn rsa_pem_import_export_roundtrip() {
    let kp = rsa::generate_keypair(rsa::RsaKeySize::Rsa2048).unwrap();

    let priv_pem = rsa::export_private_key_pem(&kp.private_key).unwrap();
    let pub_pem = rsa::export_public_key_pem(&kp.public_key).unwrap();

    let priv_imported = rsa::import_private_key_pem(&priv_pem).unwrap();
    let pub_imported = rsa::import_public_key_pem(&pub_pem).unwrap();

    let ct = rsa::encrypt(&pub_imported, b"roundtrip").unwrap();
    let pt = rsa::decrypt(&priv_imported, &ct).unwrap();
    assert_eq!(&pt, b"roundtrip");
}

// ==========================================================================
// Ed25519
// ==========================================================================

#[test]
fn ed25519_keygen_sign_verify() {
    let kp = ed25519::generate_keypair();
    let msg = b"Ed25519 test";
    let sig = ed25519::sign(&kp.signing_key, msg);
    assert!(ed25519::verify(&kp.verifying_key, msg, &sig).expect("ed25519 verify"));
}

#[test]
fn ed25519_verify_tampered() {
    let kp = ed25519::generate_keypair();
    let sig = ed25519::sign(&kp.signing_key, b"real");
    assert!(!ed25519::verify(&kp.verifying_key, b"fake", &sig).unwrap_or(false));
}

#[test]
fn ed25519_fingerprint_consistent() {
    let kp = ed25519::generate_keypair();
    let fp1 = ed25519::fingerprint(&kp.verifying_key);
    let fp2 = ed25519::fingerprint(&kp.verifying_key);
    assert_eq!(fp1, fp2);
    assert!(!fp1.is_empty());
}

#[test]
fn ed25519_pem_roundtrip() {
    let kp = ed25519::generate_keypair();
    let sk_pem = ed25519::export_signing_key_pem(&kp.signing_key).unwrap();
    let vk_pem = ed25519::export_verifying_key_pem(&kp.verifying_key).unwrap();

    let sk = ed25519::import_signing_key_pem(&sk_pem).unwrap();
    let vk = ed25519::import_verifying_key_pem(&vk_pem).unwrap();

    let sig = ed25519::sign(&sk, b"pem roundtrip");
    assert!(ed25519::verify(&vk, b"pem roundtrip", &sig).unwrap());
}

// ==========================================================================
// X25519
// ==========================================================================

#[test]
fn x25519_key_agreement() {
    let kp_a = x25519::generate_keypair();
    let kp_b = x25519::generate_keypair();

    let shared_a = x25519::key_agreement(&kp_a.secret_key, &kp_b.public_key).unwrap();
    let shared_b = x25519::key_agreement(&kp_b.secret_key, &kp_a.public_key).unwrap();
    assert_eq!(shared_a, shared_b);
}

#[test]
fn x25519_ephemeral_agreement() {
    let kp = x25519::generate_keypair();
    let (eph_pub, eph_shared) = x25519::ephemeral_key_agreement(&kp.public_key).unwrap();

    let recv_shared = x25519::key_agreement(&kp.secret_key, &eph_pub).unwrap();
    assert_eq!(eph_shared, recv_shared);
}

#[test]
fn x25519_fingerprint_consistent() {
    let kp = x25519::generate_keypair();
    let fp1 = x25519::fingerprint(&kp.public_key);
    let fp2 = x25519::fingerprint(&kp.public_key);
    assert_eq!(fp1, fp2);
    assert!(!fp1.is_empty());
}

#[test]
fn x25519_raw_export_import() {
    let kp = x25519::generate_keypair();
    let pk_bytes = x25519::export_public_key_raw(&kp.public_key);
    let pk_imported = x25519::import_public_key_raw(&pk_bytes).unwrap();
    assert_eq!(
        x25519::fingerprint(&kp.public_key),
        x25519::fingerprint(&pk_imported),
    );
}

// ==========================================================================
// KeyStore
// ==========================================================================

#[test]
fn keystore_store_and_load_keypair() {
    let dir = TempDir::new().unwrap();
    let mut ks = keystore::KeyStore::open(dir.path().to_path_buf()).expect("keystore open");

    let kp = ed25519::generate_keypair();
    let sk_bytes = ed25519::export_signing_key_raw(&kp.signing_key);
    let vk_bytes = ed25519::export_verifying_key_raw(&kp.verifying_key);
    let fp = ed25519::fingerprint(&kp.verifying_key);

    ks.store_public_key(&fp, &vk_bytes, KeyAlgorithm::Ed25519, "test-key")
        .expect("store pub");
    ks.store_private_key(
        &fp,
        &sk_bytes,
        b"pass123",
        KeyAlgorithm::Ed25519,
        "test-key",
    )
    .expect("store priv");

    let loaded_pub = ks.load_public_key(&fp).expect("load pub");
    assert_eq!(loaded_pub, vk_bytes);

    let loaded_priv = ks.load_private_key(&fp, b"pass123").expect("load priv");
    assert_eq!(loaded_priv, sk_bytes);

    assert!(ks.load_private_key(&fp, b"wrong").is_err());
}

#[test]
fn keystore_list_and_delete() {
    let dir = TempDir::new().unwrap();
    let mut ks = keystore::KeyStore::open(dir.path().to_path_buf()).unwrap();

    let kp = ed25519::generate_keypair();
    let vk_bytes = ed25519::export_verifying_key_raw(&kp.verifying_key);
    let fp = ed25519::fingerprint(&kp.verifying_key);

    ks.store_public_key(&fp, &vk_bytes, KeyAlgorithm::Ed25519, "my-key")
        .unwrap();

    let keys = ks.list_keys();
    assert!(keys.iter().any(|k| k.fingerprint == fp));

    ks.delete_key(&fp).unwrap();
    let keys2 = ks.list_keys();
    assert!(!keys2.iter().any(|k| k.fingerprint == fp));
}

#[test]
fn keystore_contacts() {
    let dir = TempDir::new().unwrap();
    let mut ks = keystore::KeyStore::open(dir.path().to_path_buf()).unwrap();

    ks.add_contact("Alice", Some("alice@example.com"), None)
        .expect("add contact");
    let contacts = ks.list_contacts();
    assert_eq!(contacts.len(), 1);
    assert_eq!(contacts[0].name, "Alice");
    assert_eq!(contacts[0].email.as_deref(), Some("alice@example.com"));

    ks.remove_contact("Alice").unwrap();
    assert!(ks.list_contacts().is_empty());
}

#[test]
fn keystore_associate_key() {
    let dir = TempDir::new().unwrap();
    let mut ks = keystore::KeyStore::open(dir.path().to_path_buf()).unwrap();

    let kp = ed25519::generate_keypair();
    let vk_bytes = ed25519::export_verifying_key_raw(&kp.verifying_key);
    let fp = ed25519::fingerprint(&kp.verifying_key);

    ks.store_public_key(&fp, &vk_bytes, KeyAlgorithm::Ed25519, "assoc-key")
        .unwrap();
    ks.add_contact("Bob", None, None).unwrap();
    ks.associate_key_with_contact("Bob", &fp).unwrap();

    let bob = ks.get_contact("Bob").unwrap();
    assert!(bob.key_fingerprints.contains(&fp));
}

// ==========================================================================
// OpenPGP
// ==========================================================================

#[test]
fn openpgp_keygen_encrypt_decrypt() {
    let cert = openpgp::generate_cert("Test User <test@example.com>").expect("pgp keygen");
    let pub_arm = openpgp::export_public_key(&cert).unwrap();
    let sec_arm = openpgp::export_secret_key(&cert).unwrap();
    assert!(pub_arm.contains("BEGIN PGP PUBLIC KEY"));
    assert!(sec_arm.contains("BEGIN PGP PRIVATE KEY"));

    let ct = openpgp::encrypt_message(b"PGP roundtrip", &[&cert]).expect("pgp encrypt");
    let pt = openpgp::decrypt_message(&ct, &[cert]).expect("pgp decrypt");
    assert_eq!(&pt, b"PGP roundtrip");
}

#[test]
fn openpgp_sign_verify() {
    let cert = openpgp::generate_cert("Signer <s@example.com>").unwrap();
    let msg = b"PGP signing test";
    let signed = openpgp::sign_message(msg, &cert).expect("pgp sign");
    let (content, valid) = openpgp::verify_message(&signed, &[cert]).expect("pgp verify");
    assert!(valid);
    assert_eq!(content, msg);
}

#[test]
fn openpgp_fingerprint_and_uid() {
    let uid = "FP Test <fp@test.com>";
    let cert = openpgp::generate_cert(uid).unwrap();
    let fp = openpgp::cert_fingerprint(&cert);
    assert!(!fp.is_empty());
    let extracted_uid = openpgp::cert_user_id(&cert);
    assert!(extracted_uid.as_deref().unwrap_or("").contains("FP Test"));
}

// ==========================================================================
// Audit logging
// ==========================================================================

#[test]
fn audit_log_and_read() {
    use hb_zayfer_core::audit::{AuditLogger, AuditOperation};
    let dir = TempDir::new().unwrap();
    let logger = AuditLogger::new(dir.path().join("audit.log"));
    logger
        .log(
            AuditOperation::FileEncrypted {
                algorithm: "AES-256-GCM".into(),
                filename: Some("/tmp/test.txt".into()),
                size_bytes: Some(1024),
            },
            Some("test note".into()),
        )
        .unwrap();
    let entries = logger.read_entries().unwrap();
    assert_eq!(entries.len(), 1);
    assert_eq!(logger.entry_count().unwrap(), 1);
}

#[test]
fn audit_integrity_chain() {
    use hb_zayfer_core::audit::{AuditLogger, AuditOperation};
    let dir = TempDir::new().unwrap();
    let logger = AuditLogger::new(dir.path().join("audit.log"));
    for i in 0..5 {
        logger
            .log(
                AuditOperation::FileDecrypted {
                    algorithm: "ChaCha20".into(),
                    filename: Some(format!("/tmp/file_{i}.hbzf")),
                    size_bytes: None,
                },
                None,
            )
            .unwrap();
    }
    assert!(
        logger.verify_integrity().unwrap(),
        "Audit chain should be valid"
    );
}

#[test]
fn audit_entry_self_verify() {
    use hb_zayfer_core::audit::{AuditEntry, AuditOperation};
    let entry = AuditEntry::new(
        AuditOperation::KeyGenerated {
            algorithm: "Ed25519".into(),
            fingerprint: "abc123".into(),
        },
        None,
        None,
    );
    assert!(entry.verify(), "Fresh entry should self-verify");
}

#[test]
fn audit_export() {
    use hb_zayfer_core::audit::{AuditLogger, AuditOperation};
    let dir = TempDir::new().unwrap();
    let logger = AuditLogger::new(dir.path().join("audit.log"));
    logger
        .log(
            AuditOperation::KeyGenerated {
                algorithm: "RSA-4096".into(),
                fingerprint: "deadbeef".into(),
            },
            None,
        )
        .unwrap();
    let export_path = dir.path().join("exported.log");
    logger.export(&export_path).unwrap();
    assert!(export_path.exists());
}

#[test]
fn audit_detects_tampered_entry() {
    use hb_zayfer_core::audit::{AuditLogger, AuditOperation};
    use std::fs;
    let dir = TempDir::new().unwrap();
    let log_path = dir.path().join("audit.log");
    let logger = AuditLogger::new(log_path.clone());
    for i in 0..3 {
        logger
            .log(
                AuditOperation::KeyGenerated {
                    algorithm: "Ed25519".into(),
                    fingerprint: format!("fp{i}"),
                },
                None,
            )
            .unwrap();
    }
    assert!(logger.verify_integrity().unwrap());

    // Tamper with the file: flip one byte in the middle line.
    let raw = fs::read(&log_path).unwrap();
    let mut tampered = raw.clone();
    let mid = tampered.len() / 2;
    tampered[mid] ^= 0x01;
    fs::write(&log_path, tampered).unwrap();

    // Either the JSON now fails to parse (HbError) or the chain
    // verification returns false; both are acceptable detection signals.
    match logger.verify_integrity() {
        Ok(valid) => assert!(!valid, "tampered chain must not verify as valid"),
        Err(_) => { /* parse error is also detection */ }
    }
}

#[test]
fn audit_detects_truncated_log() {
    use hb_zayfer_core::audit::{AuditLogger, AuditOperation};
    use std::fs::OpenOptions;
    let dir = TempDir::new().unwrap();
    let log_path = dir.path().join("audit.log");
    let logger = AuditLogger::new(log_path.clone());
    for i in 0..4 {
        logger
            .log(
                AuditOperation::KeyGenerated {
                    algorithm: "Ed25519".into(),
                    fingerprint: format!("fp{i}"),
                },
                None,
            )
            .unwrap();
    }
    let initial = logger.entry_count().unwrap();
    assert_eq!(initial, 4);
    // Truncate the file to half its size: the resulting last line is
    // partial JSON, which the logger must surface as an error or a count
    // strictly less than 4 valid entries.
    let len = std::fs::metadata(&log_path).unwrap().len();
    OpenOptions::new()
        .write(true)
        .open(&log_path)
        .unwrap()
        .set_len(len / 2)
        .unwrap();
    match logger.entry_count() {
        Ok(n) => assert!(n < initial, "truncated log must report fewer entries"),
        Err(_) => { /* parse error is acceptable */ }
    }
}

#[test]
fn keystore_check_usage_enforces_expiry() {
    use chrono::{Duration, Utc};
    use hb_zayfer_core::keystore::{KeyMetadata, KeyUsage};
    let mut meta = KeyMetadata {
        fingerprint: "deadbeef".into(),
        algorithm: hb_zayfer_core::keystore::KeyAlgorithm::Ed25519,
        label: "test".into(),
        created_at: Utc::now(),
        has_private: true,
        has_public: true,
        allowed_usages: None,
        expires_at: None,
    };
    // No expiry, no usage constraint → all operations allowed.
    assert!(meta.check_usage(KeyUsage::Sign).is_ok());

    // Expired key: any usage should be rejected.
    meta.expires_at = Some(Utc::now() - Duration::days(1));
    assert!(meta.check_usage(KeyUsage::Sign).is_err());

    // Future expiry + usage constraint: only listed usage permitted.
    meta.expires_at = Some(Utc::now() + Duration::days(7));
    meta.allowed_usages = Some(vec![KeyUsage::Verify]);
    assert!(meta.check_usage(KeyUsage::Verify).is_ok());
    assert!(meta.check_usage(KeyUsage::Sign).is_err());
}

#[test]
fn keystore_check_expiring_keys_buckets_correctly() {
    use chrono::{Duration, Utc};
    use hb_zayfer_core::ed25519;
    use hb_zayfer_core::keystore::{KeyAlgorithm, KeyExpiryStatus, KeyStore};
    let dir = TempDir::new().unwrap();
    let mut ks = KeyStore::open(dir.path().to_path_buf()).unwrap();

    // Seed three Ed25519 public keys with distinct fingerprints.
    let kp_e = ed25519::generate_keypair();
    let kp_s = ed25519::generate_keypair();
    let kp_f = ed25519::generate_keypair();
    let pk_e = ed25519::export_verifying_key_raw(&kp_e.verifying_key);
    let pk_s = ed25519::export_verifying_key_raw(&kp_s.verifying_key);
    let pk_f = ed25519::export_verifying_key_raw(&kp_f.verifying_key);
    let fp_e = ed25519::fingerprint(&kp_e.verifying_key);
    let fp_s = ed25519::fingerprint(&kp_s.verifying_key);
    let fp_f = ed25519::fingerprint(&kp_f.verifying_key);

    ks.store_public_key(&fp_e, &pk_e, KeyAlgorithm::Ed25519, "expired")
        .unwrap();
    ks.store_public_key(&fp_s, &pk_s, KeyAlgorithm::Ed25519, "soon")
        .unwrap();
    ks.store_public_key(&fp_f, &pk_f, KeyAlgorithm::Ed25519, "far")
        .unwrap();

    ks.set_key_expiry(&fp_e, Some(Utc::now() - Duration::days(2)))
        .unwrap();
    ks.set_key_expiry(&fp_s, Some(Utc::now() + Duration::days(3)))
        .unwrap();
    ks.set_key_expiry(&fp_f, Some(Utc::now() + Duration::days(365)))
        .unwrap();

    let results = ks.check_expiring_keys(7);
    // Only the expired and "soon" keys fall within a 7-day window.
    assert_eq!(results.len(), 2);
    // Expired must come first (sort order by status).
    assert!(matches!(results[0].1, KeyExpiryStatus::Expired));
    assert!(matches!(results[1].1, KeyExpiryStatus::ExpiringSoon { .. }));
}

// ==========================================================================
// Config
// ==========================================================================

#[test]
fn config_save_load_roundtrip() {
    use hb_zayfer_core::config::Config;
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("config.toml");
    let cfg = Config {
        chunk_size: 1024 * 256,
        ..Config::default()
    };
    cfg.save(&path).unwrap();
    let loaded = Config::load(&path).unwrap();
    assert_eq!(loaded.chunk_size, 1024 * 256);
}

#[test]
fn config_set_get() {
    use hb_zayfer_core::config::Config;
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("config.toml");
    let mut cfg = Config::default();
    cfg.set("chunk_size", "524288").unwrap();
    assert_eq!(cfg.get("chunk_size").unwrap(), "524288");
    cfg.save(&path).unwrap();
    let loaded = Config::load(&path).unwrap();
    assert_eq!(loaded.chunk_size, 524288);
}

// ==========================================================================
// Backup & Restore
// ==========================================================================

#[test]
fn backup_create_verify_restore() {
    // Create a keystore with an Ed25519 key
    let ks_dir = TempDir::new().unwrap();
    let mut ks = KeyStore::open(ks_dir.path().to_path_buf()).unwrap();

    let kp = ed25519::generate_keypair();
    let priv_pem = ed25519::export_signing_key_pem(&kp.signing_key).unwrap();
    let pub_pem = ed25519::export_verifying_key_pem(&kp.verifying_key).unwrap();
    let fp = keystore::compute_fingerprint(pub_pem.as_bytes());
    ks.store_private_key(
        &fp,
        priv_pem.as_bytes(),
        b"backuptest",
        KeyAlgorithm::Ed25519,
        "Backup Test Key",
    )
    .unwrap();
    ks.store_public_key(
        &fp,
        pub_pem.as_bytes(),
        KeyAlgorithm::Ed25519,
        "Backup Test Key",
    )
    .unwrap();

    // Create backup
    let backup_dir = TempDir::new().unwrap();
    let backup_path = backup_dir.path().join("test.hbzfbk");
    ks.create_backup(&backup_path, b"backup-pass", Some("test backup".into()))
        .unwrap();
    assert!(backup_path.exists());

    // Verify backup
    let manifest = KeyStore::verify_backup(&backup_path, b"backup-pass").unwrap();
    assert_eq!(manifest.label.as_deref(), Some("test backup"));

    // Restore to new location
    let restore_dir = TempDir::new().unwrap();
    let restore_manifest =
        KeyStore::restore_backup(&backup_path, b"backup-pass", restore_dir.path()).unwrap();
    assert_eq!(restore_manifest.label.as_deref(), Some("test backup"));
}

// ==========================================================================
// Format: stream encryption round-trip
// ==========================================================================

#[test]
fn format_encrypt_decrypt_bytes_aes() {
    let key = kdf::generate_salt(32);
    let plaintext = b"Hello stream world \xe2\x80\x94 AES";
    let (nonce, ct) =
        format::encrypt_bytes(plaintext, &key, format::SymmetricAlgorithm::Aes256Gcm).unwrap();
    assert!(!ct.is_empty());
    let pt =
        format::decrypt_bytes(&nonce, &ct, &key, format::SymmetricAlgorithm::Aes256Gcm).unwrap();
    assert_eq!(&pt, plaintext);
}

#[test]
fn format_encrypt_decrypt_bytes_chacha() {
    let key = kdf::generate_salt(32);
    let plaintext = b"Hello stream world \xe2\x80\x94 ChaCha";
    let (nonce, ct) = format::encrypt_bytes(
        plaintext,
        &key,
        format::SymmetricAlgorithm::ChaCha20Poly1305,
    )
    .unwrap();
    let pt = format::decrypt_bytes(
        &nonce,
        &ct,
        &key,
        format::SymmetricAlgorithm::ChaCha20Poly1305,
    )
    .unwrap();
    assert_eq!(&pt, plaintext);
}

#[test]
fn format_wrong_key_fails() {
    let key = kdf::generate_salt(32);
    let wrong_key = kdf::generate_salt(32);
    let plaintext = b"Secret stuff";
    let (nonce, ct) =
        format::encrypt_bytes(plaintext, &key, format::SymmetricAlgorithm::Aes256Gcm).unwrap();
    let result = format::decrypt_bytes(
        &nonce,
        &ct,
        &wrong_key,
        format::SymmetricAlgorithm::Aes256Gcm,
    );
    assert!(result.is_err(), "Decryption with wrong key should fail");
}

// ==========================================================================
// Error module: help_text & user_message
// ==========================================================================

mod error_tests {
    use hb_zayfer_core::error::HbError;

    #[test]
    fn help_text_invalid_passphrase() {
        let e = HbError::InvalidPassphrase;
        let help = e.help_text();
        assert!(
            help.contains("Wrong passphrase"),
            "Should mention wrong passphrase"
        );
        assert!(help.contains("Try:"), "Should include troubleshooting tip");
    }

    #[test]
    fn help_text_key_not_found() {
        let e = HbError::KeyNotFound("abc123".into());
        let help = e.help_text();
        assert!(help.contains("abc123"));
        assert!(help.contains("keys list"));
    }

    #[test]
    fn user_message_variants() {
        assert_eq!(
            HbError::InvalidPassphrase.user_message(),
            "Wrong passphrase"
        );
        assert_eq!(
            HbError::PassphraseRequired.user_message(),
            "Passphrase required"
        );

        let msg = HbError::KeyNotFound("fp1".into()).user_message();
        assert!(msg.contains("fp1"));

        let msg = HbError::ContactNotFound("Alice".into()).user_message();
        assert!(msg.contains("Alice"));

        let msg = HbError::ContactAlreadyExists("Bob".into()).user_message();
        assert!(msg.contains("Bob"));
    }

    #[test]
    fn help_text_covers_all_branches() {
        // Exercise each match arm in help_text to ensure no panics
        let variants: Vec<HbError> = vec![
            HbError::InvalidPassphrase,
            HbError::AuthenticationFailed,
            HbError::KeyNotFound("key1".into()),
            HbError::InvalidFormat("bad header".into()),
            HbError::UnsupportedVersion(99),
            HbError::PassphraseRequired,
            HbError::KeyAlreadyExists("key2".into()),
            HbError::ContactNotFound("Nobody".into()),
            HbError::Io("permission denied".into()),
            HbError::Config("syntax error".into()),
        ];
        for v in &variants {
            let text = v.help_text();
            assert!(
                !text.is_empty(),
                "help_text for {:?} should not be empty",
                v
            );
        }
    }
}

// ==========================================================================
// KeyStore: extended management methods
// ==========================================================================

mod keystore_extended {
    use hb_zayfer_core::ed25519;
    use hb_zayfer_core::keystore::{KeyAlgorithm, KeyExpiryStatus, KeyStore, KeyUsage};
    use tempfile::TempDir;

    fn setup() -> (TempDir, KeyStore) {
        let tmp = TempDir::new().unwrap();
        let ks = KeyStore::open(tmp.path().to_path_buf()).unwrap();
        (tmp, ks)
    }

    fn store_ed25519_key(ks: &mut KeyStore, label: &str) -> String {
        let kp = ed25519::generate_keypair();
        let sk_bytes = ed25519::export_signing_key_raw(&kp.signing_key);
        let vk_bytes = ed25519::export_verifying_key_raw(&kp.verifying_key);
        let fp = ed25519::fingerprint(&kp.verifying_key);
        ks.store_public_key(&fp, &vk_bytes, KeyAlgorithm::Ed25519, label)
            .unwrap();
        ks.store_private_key(&fp, &sk_bytes, b"pass", KeyAlgorithm::Ed25519, label)
            .unwrap();
        fp
    }

    #[test]
    fn get_key_metadata() {
        let (_tmp, mut ks) = setup();
        let fp = store_ed25519_key(&mut ks, "meta-test");
        let m = ks.get_key_metadata(&fp).expect("metadata should exist");
        assert_eq!(m.algorithm, KeyAlgorithm::Ed25519);
        assert_eq!(m.label, "meta-test");
        assert!(m.has_private);
        assert!(m.has_public);
    }

    #[test]
    fn find_keys_by_label() {
        let (_tmp, mut ks) = setup();
        store_ed25519_key(&mut ks, "alpha");
        store_ed25519_key(&mut ks, "beta");
        store_ed25519_key(&mut ks, "alpha-2");

        let found = ks.find_keys_by_label("alpha");
        assert_eq!(found.len(), 2, "Should find 'alpha' and 'alpha-2'");
    }

    #[test]
    fn set_key_usage() {
        let (_tmp, mut ks) = setup();
        let fp = store_ed25519_key(&mut ks, "usage-test");
        ks.set_key_usage(&fp, Some(vec![KeyUsage::Sign, KeyUsage::Verify]))
            .unwrap();
        let m = ks.get_key_metadata(&fp).unwrap();
        let usages = m.allowed_usages.as_ref().expect("should have usages set");
        assert!(usages.contains(&KeyUsage::Sign));
        assert!(usages.contains(&KeyUsage::Verify));
        assert!(!usages.contains(&KeyUsage::Encrypt));
    }

    #[test]
    fn set_key_expiry_and_check() {
        use chrono::{Duration, Utc};
        let (_tmp, mut ks) = setup();
        let fp = store_ed25519_key(&mut ks, "expiry-test");

        // Set expiry far in the future: should not be returned as expiring
        let future = Utc::now() + Duration::days(365);
        ks.set_key_expiry(&fp, Some(future)).unwrap();
        let expiring = ks.check_expiring_keys(30);
        assert!(
            expiring.iter().all(|(m, _)| m.fingerprint != fp),
            "Key with 365-day expiry should not appear in 30-day check"
        );

        // Set expiry to 10 days from now: should appear as expiring soon
        let soon = Utc::now() + Duration::days(10);
        ks.set_key_expiry(&fp, Some(soon)).unwrap();
        let expiring = ks.check_expiring_keys(30);
        let found: Vec<_> = expiring
            .iter()
            .filter(|(m, _)| m.fingerprint == fp)
            .collect();
        assert_eq!(found.len(), 1);
        assert!(matches!(found[0].1, KeyExpiryStatus::ExpiringSoon { .. }));
    }

    #[test]
    fn update_contact() {
        let (_tmp, mut ks) = setup();
        ks.add_contact("Eve", Some("eve@old.com"), Some("original"))
            .unwrap();

        ks.update_contact("Eve", Some(Some("eve@new.com")), Some(Some("updated")))
            .unwrap();
        let c = ks.get_contact("Eve").expect("contact should exist");
        assert_eq!(c.email.as_deref(), Some("eve@new.com"));
        assert_eq!(c.notes.as_deref(), Some("updated"));
    }

    #[test]
    fn update_contact_clear_fields() {
        let (_tmp, mut ks) = setup();
        ks.add_contact("Fay", Some("fay@test.com"), Some("note"))
            .unwrap();

        // Clear email, keep notes
        ks.update_contact("Fay", Some(None), None).unwrap();
        let c = ks.get_contact("Fay").unwrap();
        assert_eq!(c.email, None);
        assert_eq!(c.notes.as_deref(), Some("note")); // unchanged
    }

    #[test]
    fn get_contact_nonexistent() {
        let (_tmp, ks) = setup();
        assert!(ks.get_contact("Nobody").is_none());
    }

    #[test]
    fn check_usage_enforcement() {
        let (_tmp, mut ks) = setup();
        let fp = store_ed25519_key(&mut ks, "usage-enforce");
        ks.set_key_usage(&fp, Some(vec![KeyUsage::Sign])).unwrap();
        let m = ks.get_key_metadata(&fp).unwrap();
        assert!(
            m.check_usage(KeyUsage::Sign).is_ok(),
            "Sign should be allowed"
        );
        assert!(
            m.check_usage(KeyUsage::Encrypt).is_err(),
            "Encrypt should be disallowed"
        );
    }
}
