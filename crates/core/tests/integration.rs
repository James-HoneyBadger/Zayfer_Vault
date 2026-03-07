//! Integration tests for hb_zayfer_core crate.
//!
//! These tests exercise the public API surface end-to-end: KDF, symmetric
//! ciphers, asymmetric key-pairs, signing/verification, the HBZF streaming
//! format, and the on-disk keystore.

use hb_zayfer_core::*;
use hb_zayfer_core::{aes_gcm, chacha20, ed25519, kdf, keystore, openpgp, rsa, x25519};
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
    let key = kdf::derive_key(b"test", &kdf::generate_salt(32), &kdf::KdfParams::default()).unwrap();
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

    let shared_a = x25519::key_agreement(&kp_a.secret_key, &kp_b.public_key);
    let shared_b = x25519::key_agreement(&kp_b.secret_key, &kp_a.public_key);
    assert_eq!(shared_a, shared_b);
}

#[test]
fn x25519_ephemeral_agreement() {
    let kp = x25519::generate_keypair();
    let (eph_pub, eph_shared) = x25519::ephemeral_key_agreement(&kp.public_key);

    let recv_shared = x25519::key_agreement(&kp.secret_key, &eph_pub);
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
    ks.store_private_key(&fp, &sk_bytes, b"pass123", KeyAlgorithm::Ed25519, "test-key")
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

    ks.store_public_key(&fp, &vk_bytes, KeyAlgorithm::Ed25519, "my-key").unwrap();

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

    ks.store_public_key(&fp, &vk_bytes, KeyAlgorithm::Ed25519, "assoc-key").unwrap();
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
