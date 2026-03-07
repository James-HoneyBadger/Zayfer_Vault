use argon2::{self, Argon2, Algorithm, Version, Params};
use scrypt::scrypt;
use rand_core::OsRng;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::error::{HbError, HbResult};

/// Supported key derivation functions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum KdfAlgorithm {
    /// Argon2id — recommended default, memory-hard.
    Argon2id,
    /// Scrypt — alternative memory-hard KDF.
    Scrypt,
}

impl KdfAlgorithm {
    pub fn id(&self) -> u8 {
        match self {
            KdfAlgorithm::Argon2id => 0x01,
            KdfAlgorithm::Scrypt => 0x02,
        }
    }

    pub fn from_id(id: u8) -> HbResult<Self> {
        match id {
            0x01 => Ok(KdfAlgorithm::Argon2id),
            0x02 => Ok(KdfAlgorithm::Scrypt),
            _ => Err(HbError::UnsupportedAlgorithm(format!("KDF ID: 0x{id:02x}"))),
        }
    }
}

/// Parameters for Argon2id.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Argon2Params {
    /// Memory cost in KiB (default: 65536 = 64 MiB).
    pub m_cost: u32,
    /// Time cost / iterations (default: 3).
    pub t_cost: u32,
    /// Parallelism (default: 1).
    pub p_cost: u32,
}

impl Default for Argon2Params {
    fn default() -> Self {
        Self {
            m_cost: 65536, // 64 MiB
            t_cost: 3,
            p_cost: 1,
        }
    }
}

/// Parameters for scrypt.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScryptParams {
    /// Log2 of N (CPU/memory cost). Default: 15 (N=32768).
    pub log_n: u8,
    /// Block size. Default: 8.
    pub r: u32,
    /// Parallelism. Default: 1.
    pub p: u32,
}

impl Default for ScryptParams {
    fn default() -> Self {
        Self {
            log_n: 15,
            r: 8,
            p: 1,
        }
    }
}

/// Combined KDF parameters.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum KdfParams {
    Argon2id(Argon2Params),
    Scrypt(ScryptParams),
}

impl KdfParams {
    pub fn algorithm(&self) -> KdfAlgorithm {
        match self {
            KdfParams::Argon2id(_) => KdfAlgorithm::Argon2id,
            KdfParams::Scrypt(_) => KdfAlgorithm::Scrypt,
        }
    }
}

impl Default for KdfParams {
    fn default() -> Self {
        KdfParams::Argon2id(Argon2Params::default())
    }
}

/// Derived key with associated salt and parameters for storage.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct DerivedKey {
    #[zeroize(skip)]
    pub salt: Vec<u8>,
    pub key: Vec<u8>,
}

/// Generate a random salt of the given length.
pub fn generate_salt(len: usize) -> Vec<u8> {
    let mut salt = vec![0u8; len];
    OsRng.fill_bytes(&mut salt);
    salt
}

/// Derive a 32-byte symmetric key from a passphrase using the specified KDF.
pub fn derive_key(passphrase: &[u8], salt: &[u8], params: &KdfParams) -> HbResult<Vec<u8>> {
    let mut output = vec![0u8; 32];

    match params {
        KdfParams::Argon2id(p) => {
            let argon2_params = Params::new(p.m_cost, p.t_cost, p.p_cost, Some(32))
                .map_err(|e| HbError::Kdf(format!("Argon2 params: {e}")))?;
            let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, argon2_params);
            argon2
                .hash_password_into(passphrase, salt, &mut output)
                .map_err(|e| HbError::Kdf(format!("Argon2: {e}")))?;
        }
        KdfParams::Scrypt(p) => {
            let params = scrypt::Params::new(p.log_n, p.r, p.p, 32)
                .map_err(|e| HbError::Kdf(format!("scrypt params: {e}")))?;
            scrypt(passphrase, salt, &params, &mut output)
                .map_err(|e| HbError::Kdf(format!("scrypt: {e}")))?;
        }
    }

    Ok(output)
}

/// Derive a key with a freshly generated salt.
pub fn derive_key_fresh(passphrase: &[u8], params: &KdfParams) -> HbResult<DerivedKey> {
    let salt = generate_salt(16);
    let key = derive_key(passphrase, &salt, params)?;
    Ok(DerivedKey { salt, key })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_argon2id_derive() {
        let params = KdfParams::default();
        let salt = generate_salt(16);
        let key1 = derive_key(b"test passphrase", &salt, &params).unwrap();
        let key2 = derive_key(b"test passphrase", &salt, &params).unwrap();
        assert_eq!(key1, key2);
        assert_eq!(key1.len(), 32);

        // Different passphrase → different key
        let key3 = derive_key(b"different passphrase", &salt, &params).unwrap();
        assert_ne!(key1, key3);
    }

    #[test]
    fn test_scrypt_derive() {
        let params = KdfParams::Scrypt(ScryptParams {
            log_n: 10, // Lower for tests
            r: 8,
            p: 1,
        });
        let salt = generate_salt(16);
        let key = derive_key(b"hello world", &salt, &params).unwrap();
        assert_eq!(key.len(), 32);
    }

    #[test]
    fn test_derive_key_fresh() {
        let params = KdfParams::default();
        let dk = derive_key_fresh(b"password123", &params).unwrap();
        assert_eq!(dk.key.len(), 32);
        assert_eq!(dk.salt.len(), 16);
    }
}
