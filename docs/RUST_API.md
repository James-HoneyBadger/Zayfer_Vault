# Rust API Reference

**`hb_zayfer_core` v1.0.0**

Complete reference for the Rust core library. **20 public modules**, organised
into symmetric crypto, asymmetric crypto, format/container, key management,
advanced features, and utilities.

---

## Crate Layout

```
hb_zayfer_core
├── aes_gcm        # AES-256-GCM AEAD
├── chacha20       # ChaCha20-Poly1305 AEAD
├── rsa            # RSA-2048/4096 OAEP + PSS
├── ed25519        # Ed25519 signing
├── x25519         # X25519 ECDH key agreement
├── openpgp        # OpenPGP (Sequoia-based)
├── kdf            # Argon2id & scrypt
├── format         # HBZF container format
├── keystore       # Key + contact storage
├── audit          # Tamper-evident audit log
├── backup         # Encrypted backup/restore
├── config         # TOML configuration
├── compression    # Deflate compression layer
├── secure_mem     # mlock-backed secure memory
├── shred          # Secure file shredding
├── passgen        # Password/passphrase generation
├── shamir         # Shamir's Secret Sharing
├── stego          # LSB steganography
├── qr             # QR key exchange URIs
└── error          # Error types
```

---

## Quick Start

```toml
# Cargo.toml
[dependencies]
hb_zayfer_core = { path = "crates/core" }
```

```rust
use hb_zayfer_core::{aes_gcm, kdf, format, HbError, HbResult};
```

---

## Error Handling

### `error`

```rust
pub enum HbError {
    Encryption(String),
    Decryption(String),
    KeyGeneration(String),
    KeyNotFound(String),
    InvalidKey(String),
    InvalidPassphrase,
    Io(std::io::Error),
    Format(String),
    Config(String),
    Audit(String),
    Backup(String),
    Kdf(String),
    Compression(String),
    Shred(String),
    Stego(String),
    Shamir(String),
    Qr(String),
}

pub type HbResult<T> = Result<T, HbError>;
```

`HbError` implements `std::error::Error`, `Display`, `From<std::io::Error>`.

---

## Symmetric Encryption

### `aes_gcm`

AES-256-GCM authenticated encryption. 32-byte key, 12-byte nonce, 16-byte tag.

```rust
pub fn encrypt(key: &[u8], plaintext: &[u8], aad: &[u8]) -> HbResult<(Vec<u8>, Vec<u8>)>
// Returns (nonce, ciphertext_with_tag)

pub fn decrypt(key: &[u8], nonce: &[u8], ciphertext: &[u8], aad: &[u8]) -> HbResult<Vec<u8>>
// Returns plaintext
```

### `chacha20`

ChaCha20-Poly1305 AEAD. Same interface as `aes_gcm`.

```rust
pub fn encrypt(key: &[u8], plaintext: &[u8], aad: &[u8]) -> HbResult<(Vec<u8>, Vec<u8>)>
pub fn decrypt(key: &[u8], nonce: &[u8], ciphertext: &[u8], aad: &[u8]) -> HbResult<Vec<u8>>
```

---

## Key Derivation — `kdf`

### Types

```rust
pub enum KdfAlgorithm { Argon2id, Scrypt }

pub struct KdfParams {
    pub algorithm: KdfAlgorithm,
    pub salt: Vec<u8>,
    // Argon2id fields
    pub m_cost: Option<u32>,    // memory KiB
    pub t_cost: Option<u32>,    // iterations
    pub p_cost: Option<u32>,    // parallelism
    // scrypt fields
    pub log_n: Option<u8>,
    pub r: Option<u32>,
    pub p: Option<u32>,
}
```

### Functions

```rust
pub fn generate_salt(len: usize) -> Vec<u8>

pub fn derive_key_argon2(
    passphrase: &[u8], salt: &[u8],
    m_cost: u32,    // default: 65536
    t_cost: u32,    // default: 3
    p_cost: u32,    // default: 1
) -> HbResult<Vec<u8>>    // 32 bytes

pub fn derive_key_scrypt(
    passphrase: &[u8], salt: &[u8],
    log_n: u8, r: u32, p: u32,
) -> HbResult<Vec<u8>>
```

---

## Asymmetric Encryption

### `rsa`

RSA-2048/4096 with OAEP-SHA256 (encrypt) and PSS-SHA256 (sign).

```rust
pub fn generate(bits: usize) -> HbResult<(String, String)>
// (private_pkcs8_pem, public_pkcs8_pem)

pub fn encrypt(public_pem: &str, plaintext: &[u8]) -> HbResult<Vec<u8>>
pub fn decrypt(private_pem: &str, ciphertext: &[u8]) -> HbResult<Vec<u8>>

pub fn sign(private_pem: &str, message: &[u8]) -> HbResult<Vec<u8>>
pub fn verify(public_pem: &str, message: &[u8], signature: &[u8]) -> HbResult<bool>

pub fn fingerprint(public_pem: &str) -> HbResult<String>
// SHA-256 of DER, hex-encoded
```

### `ed25519`

Ed25519 pure signatures.

```rust
pub fn generate() -> HbResult<(String, String)>
// (signing_pem, verifying_pem)

pub fn sign(signing_pem: &str, message: &[u8]) -> HbResult<Vec<u8>>   // 64 bytes
pub fn verify(verifying_pem: &str, message: &[u8], signature: &[u8]) -> HbResult<bool>
pub fn fingerprint(verifying_pem: &str) -> HbResult<String>
```

### `x25519`

X25519 Diffie-Hellman key agreement.

```rust
pub fn generate() -> HbResult<([u8; 32], [u8; 32])>
// (secret_raw, public_raw)

pub fn encrypt_key_agreement(their_public: &[u8]) -> HbResult<([u8; 32], [u8; 32])>
// (ephemeral_public, symmetric_key)

pub fn decrypt_key_agreement(secret: &[u8], ephemeral_public: &[u8]) -> HbResult<[u8; 32]>
// symmetric_key

pub fn fingerprint(public_raw: &[u8]) -> String
```

### `openpgp`

OpenPGP (Sequoia PGP) key generation, encryption, signing.

```rust
pub fn generate(user_id: &str) -> HbResult<(String, String)>
// (public_armored, secret_armored)

pub fn encrypt(plaintext: &[u8], recipient_public_keys: &[&str]) -> HbResult<Vec<u8>>
pub fn decrypt(ciphertext: &[u8], secret_key: &str) -> HbResult<Vec<u8>>

pub fn sign(message: &[u8], secret_key: &str) -> HbResult<Vec<u8>>
pub fn verify(signed_message: &[u8], public_key: &str) -> HbResult<(Vec<u8>, bool)>

pub fn fingerprint(armored_key: &str) -> HbResult<String>
pub fn user_id(armored_key: &str) -> HbResult<Option<String>>
```

---

## HBZF Container Format — `format`

### Types

```rust
pub enum SymmetricAlgorithm { Aes256Gcm, ChaCha20Poly1305 }
pub enum KeyWrapping { Password, Rsa, X25519 }
```

### Functions

```rust
pub fn encrypt_data(
    plaintext: &[u8],
    algorithm: SymmetricAlgorithm,
    wrapping: KeyWrapping,
    passphrase: Option<&[u8]>,
    recipient_public_pem: Option<&str>,
    recipient_public_raw: Option<&[u8]>,
) -> HbResult<Vec<u8>>

pub fn decrypt_data(
    data: &[u8],
    passphrase: Option<&[u8]>,
    private_pem: Option<&str>,
    secret_raw: Option<&[u8]>,
) -> HbResult<Vec<u8>>

pub fn encrypt_file<P: AsRef<Path>, Q: AsRef<Path>>(
    input: P, output: Q,
    algorithm: SymmetricAlgorithm,
    wrapping: KeyWrapping,
    passphrase: Option<&[u8]>,
    recipient_public_pem: Option<&str>,
    recipient_public_raw: Option<&[u8]>,
) -> HbResult<u64>           // bytes written

pub fn decrypt_file<P: AsRef<Path>, Q: AsRef<Path>>(
    input: P, output: Q,
    passphrase: Option<&[u8]>,
    private_pem: Option<&str>,
    secret_raw: Option<&[u8]>,
) -> HbResult<u64>
```

---

## Key Management — `keystore`

### `KeyStore`

```rust
pub struct KeyStore { /* private */ }

impl KeyStore {
    pub fn open(path: impl AsRef<Path>) -> HbResult<Self>
    pub fn open_default() -> HbResult<Self>

    // Key operations
    pub fn store_private_key(&self, fp: &str, key: &[u8],
        passphrase: &[u8], algorithm: KeyAlgorithm, label: &str) -> HbResult<()>
    pub fn store_public_key(&self, fp: &str, key: &[u8],
        algorithm: KeyAlgorithm, label: &str) -> HbResult<()>
    pub fn load_private_key(&self, fp: &str, passphrase: &[u8]) -> HbResult<Vec<u8>>
    pub fn load_public_key(&self, fp: &str) -> HbResult<Vec<u8>>
    pub fn list_keys(&self) -> HbResult<Vec<KeyMetadata>>
    pub fn get_key_metadata(&self, fp: &str) -> HbResult<Option<KeyMetadata>>
    pub fn find_keys_by_label(&self, query: &str) -> HbResult<Vec<KeyMetadata>>
    pub fn delete_key(&self, fp: &str) -> HbResult<()>

    // Contact operations
    pub fn add_contact(&self, name: &str, email: Option<&str>,
        notes: Option<&str>) -> HbResult<()>
    pub fn associate_key_with_contact(&self, name: &str, fp: &str) -> HbResult<()>
    pub fn get_contact(&self, name: &str) -> HbResult<Option<Contact>>
    pub fn list_contacts(&self) -> HbResult<Vec<Contact>>
    pub fn remove_contact(&self, name: &str) -> HbResult<()>
    pub fn resolve_recipient(&self, name_or_fp: &str) -> HbResult<Vec<String>>
}
```

### `KeyMetadata`

```rust
pub struct KeyMetadata {
    pub fingerprint: String,
    pub algorithm: KeyAlgorithm,
    pub label: String,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub has_private: bool,
    pub has_public: bool,
    pub usage: Option<KeyUsage>,
    pub expires_at: Option<chrono::DateTime<chrono::Utc>>,
}
```

### `KeyAlgorithm`

```rust
pub enum KeyAlgorithm {
    Rsa2048, Rsa4096,
    Ed25519, X25519,
    OpenPgp,
}
```

### `KeyUsage`

```rust
pub enum KeyUsage {
    EncryptOnly,
    SignOnly,
    EncryptAndSign,
}
```

### `KeyExpiryStatus`

```rust
pub enum KeyExpiryStatus {
    NoExpiry,
    Valid { expires_at: DateTime<Utc> },
    Expired { expired_at: DateTime<Utc> },
}
```

### `Contact`

```rust
pub struct Contact {
    pub name: String,
    pub email: Option<String>,
    pub key_fingerprints: Vec<String>,
    pub notes: Option<String>,
    pub created_at: chrono::DateTime<chrono::Utc>,
}
```

---

## Audit Logging — `audit`

### Types

```rust
pub enum AuditOperation {
    KeyGenerated { algorithm: String, fingerprint: String },
    FileEncrypted { algorithm: String, filename: Option<String>, size_bytes: Option<u64> },
    FileDecrypted { algorithm: String, filename: Option<String>, size_bytes: Option<u64> },
    DataSigned { algorithm: String, fingerprint: String },
    SignatureVerified { algorithm: String, fingerprint: String, valid: bool },
    ContactAdded { name: String },
    ContactDeleted { name: String },
    KeyDeleted { fingerprint: String },
}

pub struct AuditEntry {
    pub timestamp: chrono::DateTime<chrono::Utc>,
    pub operation: AuditOperation,
    pub note: Option<String>,
    pub prev_hash: Option<String>,
    pub entry_hash: String,
}
```

### `AuditLogger`

```rust
pub struct AuditLogger { /* private */ }

impl AuditLogger {
    pub fn open(path: impl AsRef<Path>) -> HbResult<Self>
    pub fn open_default() -> HbResult<Self>
    pub fn log(&mut self, operation: AuditOperation, note: Option<&str>) -> HbResult<()>
    pub fn recent_entries(&self, limit: usize) -> HbResult<Vec<AuditEntry>>
    pub fn verify_integrity(&self) -> HbResult<bool>
    pub fn export(&self, destination: impl AsRef<Path>) -> HbResult<()>
    pub fn entry_count(&self) -> HbResult<usize>
}
```

Entries form a hash chain: each `entry_hash` commits to the previous entry,
providing tamper evidence.

---

## Backup & Restore — `backup`

```rust
pub struct BackupManifest {
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub private_key_count: usize,
    pub public_key_count: usize,
    pub contact_count: usize,
    pub version: u32,
    pub label: Option<String>,
    pub integrity_hash: String,
}

pub fn create_backup(
    keystore: &KeyStore, output: impl AsRef<Path>,
    passphrase: &[u8], label: Option<&str>,
) -> HbResult<()>

pub fn restore_backup(
    keystore: &KeyStore, backup: impl AsRef<Path>,
    passphrase: &[u8],
) -> HbResult<BackupManifest>

pub fn verify_backup(
    backup: impl AsRef<Path>, passphrase: &[u8],
) -> HbResult<BackupManifest>
```

---

## Configuration — `config`

### Types

```rust
pub struct Config {
    pub default_algorithm: SymmetricAlgorithm,
    pub default_kdf: KdfPreset,
    pub gui: GuiConfig,
    pub cli: CliConfig,
}

pub enum KdfPreset { Low, Standard, High, Paranoid }

pub struct GuiConfig {
    pub theme: String,           // "dark", "light", "auto"
    pub font_size: f64,
    pub confirm_shred: bool,
}

pub struct CliConfig {
    pub color: bool,
    pub json_output: bool,
}
```

### Functions

```rust
pub fn load() -> HbResult<Config>
pub fn load_from(path: impl AsRef<Path>) -> HbResult<Config>
pub fn save(config: &Config) -> HbResult<()>
pub fn save_to(config: &Config, path: impl AsRef<Path>) -> HbResult<()>
pub fn config_path() -> PathBuf
pub fn get(key: &str) -> HbResult<String>
pub fn set(key: &str, value: &str) -> HbResult<()>
pub fn list_settings() -> HbResult<Vec<(String, String)>>
pub fn reset() -> HbResult<Config>
```

---

## Compression — `compression`

Transparent deflate compression with a 1-byte magic header.

```rust
/// Compress; header 0x01 = compressed, 0x00 = stored.
pub fn compress(data: &[u8]) -> HbResult<Vec<u8>>

/// Decompress data produced by `compress`.
pub fn decompress(data: &[u8]) -> HbResult<Vec<u8>>

/// Returns true if `data_len` exceeds `threshold` (None → 1 KiB default).
pub fn should_compress(data_len: u64, threshold: Option<u64>) -> bool

/// Compress only if exceeding threshold; always decompressible via `decompress`.
pub fn maybe_compress(data: &[u8], threshold: Option<u64>) -> HbResult<Vec<u8>>
```

---

## Secure Memory — `secure_mem`

### `SecureBytes`

An `mlock(2)`-backed byte buffer that is zeroized on `Drop`.

```rust
pub struct SecureBytes { /* inner: Vec<u8>, locked: bool – private */ }

impl SecureBytes {
    /// Take ownership of `data` and lock it in physical memory.
    pub fn new(data: Vec<u8>) -> Self

    /// Create a zero-filled buffer of `len`, already locked.
    pub fn zeroed(len: usize) -> Self

    /// Consume self, returning the inner bytes WITHOUT zeroizing.
    pub fn into_inner(mut self) -> Vec<u8>
}
```

**Trait implementations:**

| Trait | Behaviour |
|-------|-----------|
| `Deref<Target = [u8]>` | Transparent slice access |
| `DerefMut` | Mutable slice access |
| `AsRef<[u8]>` | Borrow as slice |
| `From<Vec<u8>>` | Equivalent to `SecureBytes::new(data)` |
| `Clone` | Deep clone, also locked |
| `Drop` | Zeroize via `zeroize`, then `munlock` |
| `Debug` | Redacted — prints only `len` and `locked` |

---

## Secure Shredding — `shred`

Multi-pass overwrite (random → zero → random) then `unlink`.

```rust
pub const DEFAULT_PASSES: u32 = 3;

/// Overwrite `path` with `passes` passes, truncate, sync, unlink.
pub fn shred_file<P: AsRef<Path>>(path: P, passes: u32) -> HbResult<()>

/// Recursively shred all files then remove empty dirs.
/// Returns the number of files shredded.
pub fn shred_directory<P: AsRef<Path>>(path: P, passes: u32) -> HbResult<usize>
```

---

## Password Generation — `passgen`

### `PasswordPolicy`

```rust
#[derive(Debug, Clone)]
pub struct PasswordPolicy {
    pub length: usize,        // default: 20
    pub uppercase: bool,      // default: true
    pub lowercase: bool,      // default: true
    pub digits: bool,         // default: true
    pub symbols: bool,        // default: true
    pub exclude: String,      // default: ""
}
```

### Functions

```rust
/// Generate a random password; at least one char from each enabled class.
pub fn generate_password(policy: &PasswordPolicy) -> String

/// Generate a diceware passphrase (min 3 words).
pub fn generate_passphrase(words: usize, separator: &str) -> String

/// Entropy (bits) for a password matching `policy`.
pub fn estimate_entropy(policy: &PasswordPolicy) -> f64

/// Entropy (bits) for a diceware passphrase of `word_count` words.
pub fn passphrase_entropy(word_count: usize) -> f64
```

---

## Shamir's Secret Sharing — `shamir`

Byte-level SSS over GF(2⁸).

### `Share`

```rust
#[derive(Debug, Clone)]
pub struct Share {
    pub x: u8,           // 1..=255
    pub data: Vec<u8>,   // same length as original secret
}
```

### Functions

```rust
/// Split `secret` into `n` shares; any `k` reconstruct.
/// 2 ≤ k ≤ n ≤ 255, secret must be non-empty.
pub fn split(secret: &[u8], n: u8, k: u8) -> HbResult<Vec<Share>>

/// Reconstruct from ≥ k shares (Lagrange interpolation over GF(2⁸)).
pub fn combine(shares: &[Share]) -> HbResult<Vec<u8>>

/// Encode share to portable bytes: [x][data...]
pub fn encode_share(share: &Share) -> Vec<u8>

/// Decode share from portable bytes.
pub fn decode_share(bytes: &[u8]) -> HbResult<Share>
```

**Example:**

```rust
use hb_zayfer_core::shamir;

let secret = b"my-master-key-32-bytes-long!!!!!";
let shares = shamir::split(secret, 5, 3)?;

// Reconstruct with any 3
let recovered = shamir::combine(&shares[..3])?;
assert_eq!(&recovered, &secret[..]);
```

---

## Steganography — `stego`

LSB steganography in raw RGBA pixel data.

```rust
/// Max payload bytes storable in `pixel_len` pixel bytes.
pub fn capacity(pixel_len: usize) -> usize

/// Embed `payload` into the LSBs of `pixels` (in-place).
pub fn embed_in_pixels(pixels: &mut [u8], payload: &[u8]) -> HbResult<()>

/// Extract hidden payload from `pixels`.
pub fn extract_from_pixels(pixels: &[u8]) -> HbResult<Vec<u8>>
```

---

## QR Key Exchange — `qr`

Encode/decode public keys as `hbzf-key://` URIs for QR-code exchange.

```rust
/// Encode: hbzf-key://<algo>/<base64url>?label=<label>
pub fn encode_key_uri(algorithm: &str, public_key: &[u8], label: Option<&str>) -> String

/// Decode → (algorithm, public_key_bytes, label)
pub fn decode_key_uri(uri: &str) -> HbResult<(String, Vec<u8>, Option<String>)>
```

---

## Re-exports

The crate root re-exports commonly used types:

```rust
pub use audit::{AuditLogger, AuditOperation, AuditEntry};
pub use backup::BackupManifest;
pub use config::{Config, KdfPreset, GuiConfig, CliConfig};
pub use error::{HbError, HbResult};
pub use format::{SymmetricAlgorithm, KeyWrapping};
pub use keystore::{KeyStore, KeyAlgorithm, KeyMetadata, KeyUsage, KeyExpiryStatus, Contact};
pub use kdf::{KdfParams, KdfAlgorithm};
pub use secure_mem::SecureBytes;
```

---

## Module Index

| Module | Description |
|--------|-------------|
| `aes_gcm` | AES-256-GCM AEAD |
| `audit` | Tamper-evident audit logging (hash-chain) |
| `backup` | Encrypted backup/restore of keystore |
| `chacha20` | ChaCha20-Poly1305 AEAD |
| `compression` | Transparent deflate compression layer |
| `config` | TOML configuration management |
| `ed25519` | Ed25519 signatures |
| `error` | `HbError` enum and `HbResult<T>` |
| `format` | HBZF container encrypt/decrypt |
| `kdf` | Argon2id & scrypt key derivation |
| `keystore` | Key + contact storage |
| `openpgp` | OpenPGP (Sequoia) |
| `passgen` | Password / passphrase generation |
| `qr` | QR key exchange URIs |
| `rsa` | RSA-2048/4096 (OAEP + PSS) |
| `secure_mem` | mlock-backed secure memory |
| `shamir` | Shamir's Secret Sharing |
| `shred` | Secure file shredding |
| `stego` | LSB steganography |
| `x25519` | X25519 ECDH key agreement |
