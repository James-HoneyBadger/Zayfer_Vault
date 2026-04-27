//! Property-based tests (Phase B6).
//!
//! Uses `proptest` to fuzz round-trip invariants of the symmetric AEAD
//! ciphers, Ed25519 sign/verify, and the compression layer. These are
//! complementary to the deterministic unit tests in
//! `tests/integration.rs` — proptest will explore inputs that hand-written
//! cases miss (empty buffers, single bytes, exact block boundaries, all-
//! zero plaintext, very long buffers, AAD containing nul bytes, etc.).
//!
//! Cases per property are kept modest (32) so the suite finishes in a
//! couple of seconds; bumping `PROPTEST_CASES` in the env-var lets you
//! crank coverage on demand without touching the source.

use hb_zayfer_core::{aes_gcm, chacha20, compression, ed25519};
use proptest::prelude::*;

/// Generate a uniformly random 32-byte key.
fn key_strategy() -> impl Strategy<Value = [u8; 32]> {
    proptest::array::uniform32(any::<u8>())
}

/// Plaintext: 0..=4096 bytes — enough to cross GCM block boundaries.
fn plaintext_strategy() -> impl Strategy<Value = Vec<u8>> {
    proptest::collection::vec(any::<u8>(), 0..=4096)
}

/// AAD: 0..=512 bytes — tighter than plaintext; the AEADs treat AAD
/// asymmetrically so we want it varied but not dominating runtime.
fn aad_strategy() -> impl Strategy<Value = Vec<u8>> {
    proptest::collection::vec(any::<u8>(), 0..=512)
}

proptest! {
    #![proptest_config(ProptestConfig {
        cases: 32,
        // Disable persistence to keep CI hermetic and avoid touching $HOME.
        failure_persistence: None,
        ..ProptestConfig::default()
    })]

    /// AES-256-GCM `decrypt(encrypt(x)) == x` for any plaintext + AAD.
    #[test]
    fn aes_gcm_roundtrip(
        key in key_strategy(),
        plaintext in plaintext_strategy(),
        aad in aad_strategy(),
    ) {
        let (nonce, ciphertext) = aes_gcm::encrypt(&key, &plaintext, &aad).unwrap();
        let recovered = aes_gcm::decrypt(&key, &nonce, &ciphertext, &aad).unwrap();
        prop_assert_eq!(recovered, plaintext);
    }

    /// AES-GCM with mismatched AAD must fail authentication.
    #[test]
    fn aes_gcm_aad_tamper_detected(
        key in key_strategy(),
        plaintext in plaintext_strategy(),
        aad in aad_strategy(),
        bad_aad in aad_strategy(),
    ) {
        prop_assume!(aad != bad_aad);
        let (nonce, ciphertext) = aes_gcm::encrypt(&key, &plaintext, &aad).unwrap();
        let result = aes_gcm::decrypt(&key, &nonce, &ciphertext, &bad_aad);
        prop_assert!(result.is_err());
    }

    /// ChaCha20-Poly1305 round-trip.
    #[test]
    fn chacha20_roundtrip(
        key in key_strategy(),
        plaintext in plaintext_strategy(),
        aad in aad_strategy(),
    ) {
        let (nonce, ciphertext) = chacha20::encrypt(&key, &plaintext, &aad).unwrap();
        let recovered = chacha20::decrypt(&key, &nonce, &ciphertext, &aad).unwrap();
        prop_assert_eq!(recovered, plaintext);
    }

    /// ChaCha20 with a single ciphertext bit flipped must fail Poly1305.
    #[test]
    fn chacha20_ciphertext_tamper_detected(
        key in key_strategy(),
        plaintext in plaintext_strategy().prop_filter("non-empty", |p| !p.is_empty()),
        aad in aad_strategy(),
        flip_at in any::<u32>(),
    ) {
        let (nonce, mut ciphertext) = chacha20::encrypt(&key, &plaintext, &aad).unwrap();
        // Pick a byte and flip the lowest bit.
        let idx = (flip_at as usize) % ciphertext.len();
        ciphertext[idx] ^= 0x01;
        let result = chacha20::decrypt(&key, &nonce, &ciphertext, &aad);
        prop_assert!(result.is_err());
    }

    /// Ed25519: verify(sign(m)) == Ok(true) for any message.
    #[test]
    fn ed25519_sign_verify_roundtrip(message in proptest::collection::vec(any::<u8>(), 0..=2048)) {
        let kp = ed25519::generate_keypair();
        let sig = ed25519::sign(&kp.signing_key, &message);
        prop_assert!(ed25519::verify(&kp.verifying_key, &message, &sig).unwrap());
    }

    /// Ed25519: a signature for one message never verifies for a different message.
    #[test]
    fn ed25519_signature_message_bound(
        message in proptest::collection::vec(any::<u8>(), 1..=512),
        other in proptest::collection::vec(any::<u8>(), 1..=512),
    ) {
        prop_assume!(message != other);
        let kp = ed25519::generate_keypair();
        let sig = ed25519::sign(&kp.signing_key, &message);
        prop_assert!(!ed25519::verify(&kp.verifying_key, &other, &sig).unwrap());
    }

    /// Compression: decompress(compress(x)) == x.
    #[test]
    fn compression_roundtrip(data in proptest::collection::vec(any::<u8>(), 0..=8192)) {
        let compressed = compression::compress(&data).unwrap();
        let recovered = compression::decompress(&compressed).unwrap();
        prop_assert_eq!(recovered, data);
    }
}
