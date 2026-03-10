# Python API Reference

**HB Zayfer v1.0.0**

Complete reference for the `hb_zayfer` Python package — the public API exposed
via PyO3 bindings to the Rust core. **55+ functions** and **6 classes**.

All heavy cryptographic operations release the GIL and run in native Rust.

---

## Installation

```bash
# Build from source (requires Rust ≥ 1.75 + Maturin)
maturin develop --release -m crates/python/Cargo.toml

# Install with extras
pip install -e ".[all]"       # CLI + GUI + Web + dev
pip install -e ".[cli]"       # Click CLI only
pip install -e ".[gui]"       # + PySide6 desktop
pip install -e ".[web]"       # + FastAPI web server
pip install -e ".[dev]"       # + pytest, httpx
```

---

## Module: `hb_zayfer`

All symbols are imported from the native extension (`hb_zayfer._native`) into
the top-level namespace. Type stubs are provided in `_native.pyi` (PEP 561).

```python
import hb_zayfer as hbz
```

---

## Version

```python
hbz.version() → str
```

Returns the library version string (e.g. `"1.0.0"`).

---

## Symmetric Encryption

### AES-256-GCM

```python
hbz.aes_encrypt(key: bytes, plaintext: bytes, aad: bytes) → tuple[bytes, bytes]
```

Encrypt with AES-256-GCM. Returns `(nonce, ciphertext_with_tag)`.

| Parameter | Type | Description |
|-----------|------|-------------|
| `key` | `bytes` | 32-byte encryption key |
| `plaintext` | `bytes` | Data to encrypt |
| `aad` | `bytes` | Additional authenticated data (can be `b""`) |

```python
hbz.aes_decrypt(key: bytes, nonce: bytes, ciphertext: bytes, aad: bytes) → bytes
```

Decrypt and verify AES-256-GCM ciphertext. Returns plaintext.

**Example:**

```python
key = hbz.derive_key_argon2(b"passphrase", hbz.generate_salt(32))
nonce, ct = hbz.aes_encrypt(key, b"Hello, World!", b"")
pt = hbz.aes_decrypt(key, nonce, ct, b"")
assert pt == b"Hello, World!"
```

### ChaCha20-Poly1305

```python
hbz.chacha_encrypt(key: bytes, plaintext: bytes, aad: bytes) → tuple[bytes, bytes]
hbz.chacha_decrypt(key: bytes, nonce: bytes, ciphertext: bytes, aad: bytes) → bytes
```

Identical API to AES-256-GCM. Same key/nonce/tag sizes.

---

## Key Derivation Functions

### `generate_salt`

```python
hbz.generate_salt(length: int) → bytes
```

Generate `length` bytes of cryptographically secure random data.

### `derive_key_argon2`

```python
hbz.derive_key_argon2(
    passphrase: bytes,
    salt: bytes,
    m_cost: int = 65536,     # Memory in KiB (default: 64 MiB)
    t_cost: int = 3,         # Iterations
    p_cost: int = 1,         # Parallelism
) → bytes
```

Derive a 32-byte key using Argon2id.

### `derive_key_scrypt`

```python
hbz.derive_key_scrypt(
    passphrase: bytes,
    salt: bytes,
    log_n: int = 15,    # log₂(N), CPU/memory cost
    r: int = 8,         # Block size
    p: int = 1,         # Parallelism
) → bytes
```

Derive a 32-byte key using scrypt.

---

## RSA (2048 / 4096)

### Key Generation

```python
hbz.rsa_generate(bits: int) → tuple[str, str]
```

Generate an RSA key pair. `bits` must be `2048` or `4096`.
Returns `(private_pem, public_pem)` as PKCS#8 PEM strings.

### Encrypt & Decrypt (RSA-OAEP SHA-256)

```python
hbz.rsa_encrypt(public_pem: str, plaintext: bytes) → bytes
hbz.rsa_decrypt(private_pem: str, ciphertext: bytes) → bytes
```

### Sign & Verify (RSA-PSS SHA-256)

```python
hbz.rsa_sign(private_pem: str, message: bytes) → bytes
hbz.rsa_verify(public_pem: str, message: bytes, signature: bytes) → bool
```

### Fingerprint

```python
hbz.rsa_fingerprint(public_pem: str) → str
```

SHA-256 of DER-encoded public key, hex-encoded (64 characters).

---

## Ed25519 Signatures

### Key Generation

```python
hbz.ed25519_generate() → tuple[str, str]
```

Returns `(signing_pem, verifying_pem)` as PKCS#8 PEM strings.

### Sign & Verify

```python
hbz.ed25519_sign(signing_pem: str, message: bytes) → bytes  # 64-byte signature
hbz.ed25519_verify(verifying_pem: str, message: bytes, signature: bytes) → bool
```

### Fingerprint

```python
hbz.ed25519_fingerprint(verifying_pem: str) → str
```

---

## X25519 ECDH Key Agreement

### Key Generation

```python
hbz.x25519_generate() → tuple[bytes, bytes]
```

Returns `(secret_raw_32, public_raw_32)` as raw 32-byte `bytes`.

### Key Agreement (Encrypt Side)

```python
hbz.x25519_encrypt_key_agreement(their_public: bytes) → tuple[bytes, bytes]
```

Returns `(ephemeral_public_32, symmetric_key_32)`.

### Key Agreement (Decrypt Side)

```python
hbz.x25519_decrypt_key_agreement(secret_raw: bytes, ephemeral_public: bytes) → bytes
```

Returns the same 32-byte symmetric key.

### Fingerprint

```python
hbz.x25519_fingerprint(public_raw: bytes) → str
```

---

## OpenPGP

### Key Generation

```python
hbz.pgp_generate(user_id: str) → tuple[str, str]
```

Returns `(public_armored, secret_armored)`.

### Encrypt & Decrypt

```python
hbz.pgp_encrypt(plaintext: bytes, recipient_public_keys: list[str]) → bytes
hbz.pgp_decrypt(ciphertext: bytes, secret_key_armored: str) → bytes
```

### Sign & Verify

```python
hbz.pgp_sign(message: bytes, secret_key_armored: str) → bytes
hbz.pgp_verify(signed_message: bytes, public_key_armored: str) → tuple[bytes, bool]
```

### Metadata

```python
hbz.pgp_fingerprint(armored_key: str) → str
hbz.pgp_user_id(armored_key: str) → Optional[str]
```

---

## HBZF File Format

### In-Memory Encrypt/Decrypt

```python
hbz.encrypt_data(
    plaintext: bytes,
    algorithm: str = "aes",           # "aes" or "chacha"
    wrapping: str = "password",       # "password", "rsa", or "x25519"
    passphrase: Optional[bytes] = None,
    recipient_public_pem: Optional[str] = None,
    recipient_public_raw: Optional[bytes] = None,
) → bytes

hbz.decrypt_data(
    data: bytes,
    passphrase: Optional[bytes] = None,
    private_pem: Optional[str] = None,
    secret_raw: Optional[bytes] = None,
) → bytes
```

### File Encrypt/Decrypt

```python
hbz.encrypt_file(
    input_path: str, output_path: str,
    algorithm: str = "aes", wrapping: str = "password",
    passphrase=None, recipient_public_pem=None, recipient_public_raw=None,
) → int  # bytes written

hbz.decrypt_file(
    input_path: str, output_path: str,
    passphrase=None, private_pem=None, secret_raw=None,
) → int  # bytes written
```

**Wrapping modes:**

| `wrapping` | Required parameter |
|------------|-------------------|
| `"password"` | `passphrase` |
| `"rsa"` | `recipient_public_pem` (encrypt) / `private_pem` (decrypt) |
| `"x25519"` | `recipient_public_raw` (encrypt) / `secret_raw` (decrypt) |

---

## Password Generation

### `generate_password`

```python
hbz.generate_password(
    length: int = 20,
    exclude: Optional[str] = None,
) → str
```

Generate a random password using alphanumeric + symbol characters.
Optionally exclude specific characters (e.g., `"0O1lI"` for ambiguous chars).

### `generate_passphrase`

```python
hbz.generate_passphrase(
    words: int = 6,
    separator: str = " ",
) → str
```

Generate a Diceware-style passphrase with `words` random words.

### `password_entropy`

```python
hbz.password_entropy(length: int) → float
```

Calculate the entropy (in bits) of a random password of the given length.

### `passphrase_entropy`

```python
hbz.passphrase_entropy(words: int) → float
```

Calculate the entropy (in bits) of a random passphrase with the given word count.

**Example:**

```python
# Random password
pw = hbz.generate_password(length=24, exclude="0O1lI")
print(f"Password: {pw}")

# Diceware passphrase
phrase = hbz.generate_passphrase(words=6, separator="-")
print(f"Passphrase: {phrase}")

# Entropy
print(f"24-char password: {hbz.password_entropy(24):.1f} bits")
print(f"6-word passphrase: {hbz.passphrase_entropy(6):.1f} bits")
```

---

## Shamir's Secret Sharing

### `shamir_split`

```python
hbz.shamir_split(
    secret: bytes,
    shares: int,
    threshold: int,
) → list[str]
```

Split a secret into `shares` shares, requiring `threshold` to reconstruct.
Returns a list of hex-encoded share strings.

### `shamir_combine`

```python
hbz.shamir_combine(shares: list[str]) → bytes
```

Reconstruct the original secret from hex-encoded shares.
Must provide at least `threshold` shares.

**Example:**

```python
# Split a secret
secret = b"master-passphrase-123"
shares = hbz.shamir_split(secret, 5, 3)  # 5 shares, need 3
print(f"Created {len(shares)} shares")

# Reconstruct with any 3 shares
recovered = hbz.shamir_combine(shares[:3])
assert recovered == secret

# Different subset works too
recovered2 = hbz.shamir_combine([shares[1], shares[3], shares[4]])
assert recovered2 == secret
```

---

## Steganography

### `stego_embed`

```python
hbz.stego_embed(image_data: bytes, message: bytes) → bytes
```

Embed a message into image pixel data using LSB (Least Significant Bit)
encoding. Returns the modified image data.

### `stego_extract`

```python
hbz.stego_extract(stego_data: bytes) → bytes
```

Extract a hidden message from stego image data.

### `stego_capacity`

```python
hbz.stego_capacity(image_data: bytes) → int
```

Calculate the maximum message size (in bytes) that can be embedded.

**Example:**

```python
# Embed a secret message
with open("photo.raw", "rb") as f:
    image_data = f.read()

stego = hbz.stego_embed(image_data, b"Hidden message!")
with open("photo_stego.raw", "wb") as f:
    f.write(stego)

# Extract the message
extracted = hbz.stego_extract(stego)
assert extracted == b"Hidden message!"

# Check capacity
cap = hbz.stego_capacity(image_data)
print(f"Can embed up to {cap} bytes")
```

---

## Secure File Shredding

### `shred_file`

```python
hbz.shred_file(path: str, passes: int = 3) → None
```

Securely overwrite a file with random data for `passes` passes, then delete it.

### `shred_directory`

```python
hbz.shred_directory(path: str, passes: int = 3) → None
```

Recursively shred all files in a directory, then remove the directory.

**Example:**

```python
# Securely delete a file
hbz.shred_file("/tmp/secret.txt", passes=3)

# Recursively shred a directory
hbz.shred_directory("/tmp/sensitive-data/", passes=5)
```

---

## QR Code Key Exchange

### `qr_encode_key_uri`

```python
hbz.qr_encode_key_uri(
    algorithm: str,
    public_key: bytes,
    label: Optional[str] = None,
) → str
```

Encode a public key as an `hbzf-key://` URI suitable for QR codes.
The `public_key` parameter accepts raw key bytes (hex-encoded in the URI).

### `qr_decode_key_uri`

```python
hbz.qr_decode_key_uri(uri: str) → tuple[str, bytes, Optional[str]]
```

Decode an `hbzf-key://` URI. Returns `(algorithm, public_key, label)`
where `public_key` is raw bytes.

**Example:**

```python
# Create a key URI
pub_key = bytes.fromhex("a1b2c3d4")
uri = hbz.qr_encode_key_uri("ed25519", pub_key, "Alice")
print(uri)  # hbzf-key://ed25519/a1b2c3d4?label=Alice

# Decode a key URI
algo, pk, label = hbz.qr_decode_key_uri(uri)
assert algo == "ed25519"
assert pk == pub_key
assert label == "Alice"
```

---

## Utilities

```python
hbz.compute_fingerprint(public_key_bytes: bytes) → str
# SHA-256 of raw bytes, hex-encoded

hbz.detect_key_format(data: bytes) → str
# Returns one of: "pkcs8_pem", "pkcs1_pem", "der", "openpgp_armor", "openssh"
```

---

## KeyStore Class

Manages cryptographic keys and contacts on disk.

### Constructor

```python
ks = hbz.KeyStore(path: Optional[str] = None)
```

If `path` is `None`, uses `$HB_ZAYFER_HOME` or `~/.hb_zayfer/`.

### Key Operations

```python
ks.store_private_key(fingerprint, key_bytes, passphrase, algorithm, label) → None
ks.store_public_key(fingerprint, key_bytes, algorithm, label) → None
ks.load_private_key(fingerprint: str, passphrase: bytes) → bytes
ks.load_public_key(fingerprint: str) → bytes
ks.list_keys() → list[KeyMetadata]
ks.get_key_metadata(fingerprint: str) → Optional[KeyMetadata]
ks.find_keys_by_label(query: str) → list[KeyMetadata]
ks.delete_key(fingerprint: str) → None
```

### Contact Operations

```python
ks.add_contact(name, email=None, notes=None) → None
ks.associate_key_with_contact(contact_name, fingerprint) → None
ks.get_contact(name) → Optional[Contact]
ks.list_contacts() → list[Contact]
ks.remove_contact(name) → None
ks.resolve_recipient(name_or_fp) → list[str]
```

### Backup Operations

```python
ks.create_backup(output_path, passphrase, label=None) → None
ks.restore_backup(backup_path, passphrase) → BackupManifest
ks.verify_backup(backup_path, passphrase) → BackupManifest
```

### KeyMetadata

| Attribute | Type | Description |
|-----------|------|-------------|
| `fingerprint` | `str` | Hex SHA-256 fingerprint |
| `algorithm` | `str` | Key algorithm name |
| `label` | `str` | Human-readable label |
| `created_at` | `str` | ISO 8601 timestamp |
| `has_private` | `bool` | Private key present |
| `has_public` | `bool` | Public key present |

### Contact

| Attribute | Type | Description |
|-----------|------|-------------|
| `name` | `str` | Contact name |
| `email` | `Optional[str]` | Email address |
| `key_fingerprints` | `list[str]` | Associated key fingerprints |
| `notes` | `Optional[str]` | Free-form notes |
| `created_at` | `str` | ISO 8601 timestamp |

### BackupManifest

| Attribute | Type | Description |
|-----------|------|-------------|
| `created_at` | `str` | ISO 8601 timestamp |
| `private_key_count` | `int` | Number of private keys |
| `public_key_count` | `int` | Number of public keys |
| `contact_count` | `int` | Number of contacts |
| `version` | `int` | Backup format version |
| `label` | `Optional[str]` | User-provided label |
| `integrity_hash` | `str` | SHA-256 integrity hash |

---

## Audit Logging

### Logging Functions

```python
hbz.audit_log_key_generated(algorithm, fingerprint, note=None) → None
hbz.audit_log_file_encrypted(algorithm, filename=None, size_bytes=None, note=None) → None
hbz.audit_log_file_decrypted(algorithm, filename=None, size_bytes=None, note=None) → None
hbz.audit_log_data_signed(algorithm, fingerprint, note=None) → None
hbz.audit_log_signature_verified(algorithm, fingerprint, valid, note=None) → None
hbz.audit_log_contact_added(name, note=None) → None
hbz.audit_log_contact_deleted(name, note=None) → None
hbz.audit_log_key_deleted(fingerprint, note=None) → None
```

### `AuditLogger`

```python
logger = hbz.AuditLogger(path: Optional[str] = None)
logger.recent_entries(limit: int = 20) → list[AuditEntry]
logger.verify_integrity() → bool
logger.export(destination: str) → None
logger.entry_count() → int
```

### `AuditEntry`

| Attribute | Type | Description |
|-----------|------|-------------|
| `timestamp` | `str` | ISO 8601 timestamp |
| `operation` | `str` | Operation type |
| `prev_hash` | `Optional[str]` | Hash of previous entry |
| `entry_hash` | `str` | SHA-256 hash of this entry |
| `note` | `Optional[str]` | Optional context note |

---

## Error Handling

All functions raise `ValueError` on failure. The error message contains
details from the Rust `HbError` variant (e.g., "Authentication failed",
"Key not found: abc123", "Invalid passphrase").

```python
try:
    hbz.aes_decrypt(wrong_key, nonce, ct, b"")
except ValueError as e:
    print(f"Decryption failed: {e}")
```

---

## Complete Function Index

| Category | Functions |
|----------|-----------|
| Version | `version` |
| AES-256-GCM | `aes_encrypt`, `aes_decrypt` |
| ChaCha20-Poly1305 | `chacha_encrypt`, `chacha_decrypt` |
| KDF | `generate_salt`, `derive_key_argon2`, `derive_key_scrypt` |
| RSA | `rsa_generate`, `rsa_encrypt`, `rsa_decrypt`, `rsa_sign`, `rsa_verify`, `rsa_fingerprint` |
| Ed25519 | `ed25519_generate`, `ed25519_sign`, `ed25519_verify`, `ed25519_fingerprint` |
| X25519 | `x25519_generate`, `x25519_encrypt_key_agreement`, `x25519_decrypt_key_agreement`, `x25519_fingerprint` |
| OpenPGP | `pgp_generate`, `pgp_encrypt`, `pgp_decrypt`, `pgp_sign`, `pgp_verify`, `pgp_fingerprint`, `pgp_user_id` |
| HBZF Format | `encrypt_data`, `decrypt_data`, `encrypt_file`, `decrypt_file` |
| Utilities | `compute_fingerprint`, `detect_key_format` |
| Audit | `audit_log_key_generated`, `audit_log_file_encrypted`, `audit_log_file_decrypted`, `audit_log_data_signed`, `audit_log_signature_verified`, `audit_log_contact_added`, `audit_log_contact_deleted`, `audit_log_key_deleted` |
| Password Gen | `generate_password`, `generate_passphrase`, `password_entropy`, `passphrase_entropy` |
| Shamir SSS | `shamir_split`, `shamir_combine` |
| Steganography | `stego_embed`, `stego_extract`, `stego_capacity` |
| Secure Shred | `shred_file`, `shred_directory` |
| QR Exchange | `qr_encode_key_uri`, `qr_decode_key_uri` |

**Classes**: `KeyStore`, `KeyMetadata`, `Contact`, `BackupManifest`, `AuditEntry`, `AuditLogger`
