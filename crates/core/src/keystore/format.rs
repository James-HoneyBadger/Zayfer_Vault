//! Public-key fingerprinting and key-file format detection.
//!
//! Split out of `keystore/mod.rs` in Phase B2.

use sha2::{Digest, Sha256};

/// Compute a fingerprint from arbitrary public key bytes.
pub fn compute_fingerprint(public_key_bytes: &[u8]) -> String {
    let hash = Sha256::digest(public_key_bytes);
    hex::encode(hash)
}

/// Auto-detect the format of a key file by inspecting its contents.
pub fn detect_key_format(data: &[u8]) -> KeyFormat {
    if let Ok(text) = std::str::from_utf8(data) {
        if text.contains("-----BEGIN PGP") {
            return KeyFormat::OpenPgpArmor;
        }
        if text.starts_with("ssh-") {
            return KeyFormat::OpenSsh;
        }
        if text.contains("-----BEGIN") {
            // Could be PKCS#1 or PKCS#8
            if text.contains("RSA PRIVATE KEY") || text.contains("RSA PUBLIC KEY") {
                return KeyFormat::Pkcs1Pem;
            }
            return KeyFormat::Pkcs8Pem;
        }
    }
    KeyFormat::Der
}

/// Key file format.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeyFormat {
    Pkcs8Pem,
    Pkcs1Pem,
    Der,
    OpenPgpArmor,
    OpenSsh,
}
