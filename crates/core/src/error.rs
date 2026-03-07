use thiserror::Error;

/// Unified error type for the HB_Zayfer crypto core.
#[derive(Error, Debug)]
pub enum HbError {
    // -- Crypto errors --
    #[error("RSA error: {0}")]
    Rsa(String),

    #[error("AES-GCM error: {0}")]
    AesGcm(String),

    #[error("ChaCha20-Poly1305 error: {0}")]
    ChaCha20(String),

    #[error("Ed25519 error: {0}")]
    Ed25519(String),

    #[error("X25519 error: {0}")]
    X25519(String),

    #[error("OpenPGP error: {0}")]
    OpenPgp(String),

    #[error("Key derivation error: {0}")]
    Kdf(String),

    // -- Key management errors --
    #[error("Key not found: {0}")]
    KeyNotFound(String),

    #[error("Key already exists: {0}")]
    KeyAlreadyExists(String),

    #[error("Invalid key format: {0}")]
    InvalidKeyFormat(String),

    #[error("Passphrase required")]
    PassphraseRequired,

    #[error("Invalid passphrase")]
    InvalidPassphrase,

    // -- File format errors --
    #[error("Invalid file format: {0}")]
    InvalidFormat(String),

    #[error("Unsupported version: {0}")]
    UnsupportedVersion(u8),

    #[error("Unsupported algorithm: {0}")]
    UnsupportedAlgorithm(String),

    #[error("Authentication failed — data may be corrupted or tampered")]
    AuthenticationFailed,

    // -- I/O errors --
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Serialization error: {0}")]
    Serialization(String),

    // -- Contact errors --
    #[error("Contact not found: {0}")]
    ContactNotFound(String),

    #[error("Contact already exists: {0}")]
    ContactAlreadyExists(String),
}

/// Result type alias for HB_Zayfer operations.
pub type HbResult<T> = Result<T, HbError>;

impl From<rsa::Error> for HbError {
    fn from(e: rsa::Error) -> Self {
        HbError::Rsa(e.to_string())
    }
}

impl From<rsa::pkcs1::Error> for HbError {
    fn from(e: rsa::pkcs1::Error) -> Self {
        HbError::InvalidKeyFormat(format!("PKCS#1: {e}"))
    }
}

impl From<rsa::pkcs8::Error> for HbError {
    fn from(e: rsa::pkcs8::Error) -> Self {
        HbError::InvalidKeyFormat(format!("PKCS#8: {e}"))
    }
}

impl From<ed25519_dalek::SignatureError> for HbError {
    fn from(e: ed25519_dalek::SignatureError) -> Self {
        HbError::Ed25519(e.to_string())
    }
}

impl From<serde_json::Error> for HbError {
    fn from(e: serde_json::Error) -> Self {
        HbError::Serialization(e.to_string())
    }
}

impl From<toml::de::Error> for HbError {
    fn from(e: toml::de::Error) -> Self {
        HbError::Serialization(format!("TOML parse: {e}"))
    }
}

impl From<toml::ser::Error> for HbError {
    fn from(e: toml::ser::Error) -> Self {
        HbError::Serialization(format!("TOML serialize: {e}"))
    }
}

impl From<base64::DecodeError> for HbError {
    fn from(e: base64::DecodeError) -> Self {
        HbError::InvalidFormat(format!("Base64: {e}"))
    }
}
