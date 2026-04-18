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
    Io(String),

    #[error("Serialization error: {0}")]
    Serialization(String),

    // -- Configuration errors --
    #[error("Configuration error: {0}")]
    Config(String),

    // -- Contact errors --
    #[error("Contact not found: {0}")]
    ContactNotFound(String),

    #[error("Contact already exists: {0}")]
    ContactAlreadyExists(String),
}
impl HbError {
    /// Get a user-friendly help message with troubleshooting tips.
    pub fn help_text(&self) -> String {
        match self {
            HbError::InvalidPassphrase => "Decryption failed. Possible causes:\n\
                 • Wrong passphrase entered\n\
                 • Key was encrypted with a different passphrase\n\
                 • File may be corrupted\n\n\
                 Try: Verify you're using the correct passphrase."
                .into(),
            HbError::AuthenticationFailed => "Authentication failed. Possible causes:\n\
                 • Wrong passphrase or key\n\
                 • File has been modified or corrupted\n\
                 • File was tampered with\n\n\
                 Try: Verify the file integrity and use the correct decryption key."
                .into(),
            HbError::KeyNotFound(fp) => {
                format!(
                    "Key '{}' not found in keystore.\n\n\
                        Try:\n\
                        • List available keys with: hb-zayfer keys list\n\
                        • Generate a new key with: hb-zayfer keys generate\n\
                        • Import an existing key with: hb-zayfer keys import",
                    fp
                )
            }
            HbError::InvalidFormat(msg) => {
                format!("File format error: {}\n\n\
                        The file may not be a valid HBZF encrypted file, or it may be corrupted.\n\n\
                        Try: Verify the file is a .hbzf file and hasn't been modified.", msg)
            }
            HbError::UnsupportedVersion(v) => {
                format!(
                    "Unsupported file version: {}\n\n\
                        This file was created with a newer or older version of HB_Zayfer.\n\n\
                        Try: Update to the latest version of HB_Zayfer.",
                    v
                )
            }
            HbError::PassphraseRequired => "Passphrase required.\n\n\
                 This key or file is password-protected and requires a passphrase to access.\n\n\
                 Try: Provide the passphrase using the --passphrase flag or when prompted."
                .into(),
            HbError::KeyAlreadyExists(fp) => {
                format!(
                    "Key '{}' already exists in keystore.\n\n\
                        Try:\n\
                        • Use a different label\n\
                        • Delete the existing key first: hb-zayfer keys delete {}\n\
                        • Export and backup the existing key before replacing",
                    fp, fp
                )
            }
            HbError::ContactNotFound(name) => {
                format!(
                    "Contact '{}' not found.\n\n\
                        Try:\n\
                        • List all contacts: hb-zayfer contacts list\n\
                        • Add the contact: hb-zayfer contacts add '{}'",
                    name, name
                )
            }
            HbError::Io(msg) => {
                format!(
                    "I/O error: {}\n\n\
                        Check:\n\
                        • File or directory exists and is accessible\n\
                        • You have sufficient permissions\n\
                        • Disk is not full",
                    msg
                )
            }
            HbError::Config(msg) => {
                format!(
                    "Configuration error: {}\n\n\
                        Try:\n\
                        • Check ~/.hb_zayfer/config.toml for syntax errors\n\
                        • Reset to defaults: rm ~/.hb_zayfer/config.toml",
                    msg
                )
            }
            _ => self.to_string(),
        }
    }

    /// Get a short user-friendly error message (one line).
    pub fn user_message(&self) -> String {
        match self {
            HbError::InvalidPassphrase => "Wrong passphrase".into(),
            HbError::AuthenticationFailed => {
                "File authentication failed - wrong key or corrupted file".into()
            }
            HbError::KeyNotFound(fp) => format!("Key '{}' not found", fp),
            HbError::PassphraseRequired => "Passphrase required".into(),
            HbError::KeyAlreadyExists(fp) => format!("Key '{}' already exists", fp),
            HbError::ContactNotFound(name) => format!("Contact '{}' not found", name),
            HbError::ContactAlreadyExists(name) => format!("Contact '{}' already exists", name),
            HbError::InvalidFormat(_) => "Invalid file format".into(),
            HbError::UnsupportedVersion(v) => format!("Unsupported version {}", v),
            _ => self.to_string(),
        }
    }
}

/// Result type alias for HB_Zayfer operations.
pub type HbResult<T> = Result<T, HbError>;

impl From<rsa::Error> for HbError {
    fn from(e: rsa::Error) -> Self {
        HbError::Rsa(e.to_string())
    }
}

impl From<std::io::Error> for HbError {
    fn from(e: std::io::Error) -> Self {
        HbError::Io(e.to_string())
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
