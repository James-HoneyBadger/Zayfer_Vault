# Architecture

**Zayfer Vault v1.0.1**

This document describes the internal architecture of Zayfer Vault, a full-featured
encryption/decryption suite built with a **Rust core**, **Python bindings**
(via PyO3), and a **WASM module** (via wasm-bindgen).

---

## High-Level Overview

```
┌──────────────────── User Interfaces ─────────────────────┐
│                                                          │
│   Rust CLI          Python CLI          Desktop GUI      │
│   (clap)            (Click + Rich)      (PySide6)        │
│                                                          │
│              Web UI (FastAPI + vanilla JS)                │
│                                                          │
├──────────────── Python Bindings (PyO3) ──────────────────┤
│                                                          │
│   hb_zayfer._native    (crates/python — cdylib)          │
│   55+ functions, 6 classes                               │
│                                                          │
├──────────────────── Rust Core Library ───────────────────┤
│                                                          │
│   hb_zayfer_core       (crates/core — rlib)              │
│                                                          │
│   ┌─────────┐ ┌───────────┐ ┌───────┐ ┌─────────┐       │
│   │ aes_gcm │ │ chacha20  │ │  rsa  │ │ ed25519 │       │
│   └─────────┘ └───────────┘ └───────┘ └─────────┘       │
│   ┌─────────┐ ┌───────────┐ ┌───────┐ ┌─────────┐       │
│   │ x25519  │ │  openpgp  │ │  kdf  │ │ format  │       │
│   └─────────┘ └───────────┘ └───────┘ └─────────┘       │
│   ┌──────────┐ ┌─────────┐ ┌────────┐ ┌─────────┐       │
│   │ keystore │ │  audit  │ │ backup │ │  config │       │
│   └──────────┘ └─────────┘ └────────┘ └─────────┘       │
│   ┌─────────────┐ ┌────────────┐ ┌─────────┐            │
│   │ compression │ │ secure_mem │ │  error  │            │
│   └─────────────┘ └────────────┘ └─────────┘            │
│   ┌───────┐ ┌─────────┐ ┌────────┐ ┌───────┐            │
│   │ shred │ │ passgen │ │ shamir │ │ stego │            │
│   └───────┘ └─────────┘ └────────┘ └───────┘            │
│   ┌──────┐                                               │
│   │  qr  │                                               │
│   └──────┘                                               │
│                                                          │
├──────────────── WASM Module (standalone) ────────────────┤
│                                                          │
│   hb_zayfer_wasm     (crates/wasm — wasm-bindgen)        │
│   13 functions: AES, ChaCha20, Ed25519, X25519, KDF      │
│                                                          │
└──────────────────────────────────────────────────────────┘
```

---

## Workspace Crates

The Cargo workspace (`Cargo.toml`) contains four crates with a shared
version (`1.0.0`):

| Crate | Path | Type | Purpose |
|-------|------|------|---------|
| `hb_zayfer_core` | `crates/core` | `rlib` | All cryptographic operations, file format, key storage, audit, backup, and security utilities |
| `hb_zayfer_cli` | `crates/cli` | `bin` | Rust-native CLI (clap + dialoguer + indicatif), 20+ commands |
| `hb_zayfer_python` | `crates/python` | `cdylib` | PyO3 bindings → `hb_zayfer._native`, 55+ functions, 6 classes |
| `hb_zayfer_wasm` | `crates/wasm` | `cdylib` | WASM module (wasm-bindgen), 13 browser-ready functions |

### Dependency Flow

```
hb_zayfer_cli ──────┐
                     ├──► hb_zayfer_core
hb_zayfer_python ───┘

hb_zayfer_wasm ──────── (standalone — no core dependency)
```

The CLI and Python bindings depend on `hb_zayfer_core`. The WASM crate is
standalone (reimplements core algorithms using pure-Rust crates compatible
with `wasm32-unknown-unknown`, since Sequoia/OpenPGP is not WASM-compatible).

---

## Core Library Modules

The core library contains **20 public modules**:

### `aes_gcm` — AES-256-GCM

- Encrypt/decrypt with 256-bit keys, 96-bit nonces, 128-bit tags.
- `encrypt_chunk` / `decrypt_chunk` for streaming with nonce-index XOR.
- Uses the RustCrypto `aes-gcm` crate.

### `chacha20` — ChaCha20-Poly1305

- Mirror API to `aes_gcm`: same key/nonce/tag sizes.
- Streaming chunk support with identical nonce derivation scheme.
- Uses the RustCrypto `chacha20poly1305` crate.

### `rsa` — RSA-OAEP & RSA-PSS

- Key generation at 2048 or 4096 bits.
- Encryption: RSA-OAEP with SHA-256 padding.
- Signing: RSA-PSS with SHA-256, blinded for side-channel resistance.
- Key serialization: PKCS#1 PEM and PKCS#8 PEM (import/export).
- Fingerprint: SHA-256 of DER-encoded public key.

### `ed25519` — Ed25519 Signatures

- Key generation via `ed25519-dalek`.
- Sign/verify with 64-byte signatures.
- Key serialization: PKCS#8 PEM and raw 32-byte formats.
- Signing key bytes are zeroized on drop.

### `x25519` — X25519 ECDH Key Agreement

- Static and ephemeral key pair generation.
- `encrypt_key_agreement`: ephemeral ECDH + HKDF-SHA256 → 32-byte symmetric key.
- `decrypt_key_agreement`: recipient-side derivation.
- Raw 32-byte key import/export.
- Secret key bytes zeroized on drop.

### `openpgp` — OpenPGP (Sequoia)

- Certificate generation with signing, transport-encryption, and storage-encryption subkeys.
- ASCII-armored import/export (public and secret keys).
- Encrypt to multiple recipients.
- Decrypt with secret key (via `DecryptionHelper`).
- Inline signing and signature verification.

### `kdf` — Key Derivation Functions

- **Argon2id**: default (m=64 MiB, t=3, p=1).
- **Scrypt**: alternative (log_n=15, r=8, p=1).
- `generate_salt(len)`: OS CSPRNG salt.
- `derive_key(passphrase, salt, params) → 32 bytes`.
- Derived key material is zeroized on drop (`DerivedKey`).

### `format` — HBZF Streaming AEAD

The custom binary format for file encryption:

```
[4B]  Magic:   "HBZF"
[1B]  Version: 0x01
[1B]  Symmetric algorithm ID:  0x01=AES, 0x02=ChaCha
[1B]  KDF algorithm ID:        0x00=none, 0x01=Argon2id, 0x02=scrypt
[1B]  Key wrapping mode:       0x00=password, 0x01=RSA-OAEP, 0x02=X25519
[var] KDF params (if KDF≠none): salt(16B) + params(12B)
[var] Wrapped key (RSA-OAEP) or ephemeral pubkey (X25519)
[12B] Base nonce
[8B]  Original plaintext length (LE u64)
[var] Stream of chunks: [4B chunk_len_le][chunk_ciphertext]
```

**Chunk encryption**: configurable chunk size (default 64 KiB) → append 16-byte AEAD tag.
Nonce derived by XOR-ing chunk index into the last 8 bytes of the base nonce.
Chunk index is also appended to AAD to prevent chunk reordering.

### `keystore` — Key & Contact Storage

On-disk layout at `~/.hb_zayfer/` (or `$HB_ZAYFER_HOME`):

```
~/.hb_zayfer/
├── keys/
│   ├── private/<fingerprint>.key  (v2 envelope: KDF params + AES-GCM encrypted)
│   └── public/<fingerprint>.pub   (plaintext key material)
├── keyring.json       (KeyMetadata index with usage constraints & expiry)
├── contacts.json      (Contact ↔ key associations)
├── audit.json         (Tamper-evident operation log with HMAC chain)
├── config.toml        (Rust core configuration — TOML)
├── config.json        (GUI / web configuration — JSON)
└── gui_settings.json  (GUI preferences: theme, geometry, defaults)
```

**Key types include**: `KeyAlgorithm` (Rsa2048, Rsa4096, Ed25519, X25519, Pgp),
`KeyUsage` (Signing, Encryption, KeyAgreement, Authentication),
`KeyExpiryStatus` (Valid, ExpiresSoon, Expired).

### `audit` — Tamper-Evident Audit Log

- Records all sensitive operations (key generation, encrypt, decrypt, sign, verify).
- Integrity chain: each entry's hash includes the previous entry's hash (HMAC-based).
- `AuditLogger` supports `recent_entries(limit)`, `verify_integrity()`, and `export(path)`.
- Stored in `audit.json`.

### `backup` — Keystore Backup & Restore

- Creates encrypted archives of the entire keystore.
- `BackupManifest` tracks version, timestamp, key/contact counts.
- Supports `create_backup`, `restore_backup`, and `verify_backup`.

### `config` — Application Configuration

- Manages default algorithm preferences, KDF parameters, and rate limiting.
- Stored in `config.json`.

### `compression` — Data Compression

- Flate2/deflate compression with configurable level.
- `compress(data)` / `decompress(data)` public API.
- Integrated into HBZF encryption pipeline (optional).

### `secure_mem` — Secure Memory

- `SecureBytes` wrapper with `Zeroize` + `ZeroizeOnDrop`.
- Used for all key material, derived keys, and sensitive intermediates.
- Prevents accidental leakage of secrets in memory dumps.

### `shred` — Secure File Shredding

- Multi-pass overwrite with cryptographically random data.
- `shred_file(path, passes)` — overwrite + unlink single file.
- `shred_directory(path, passes)` — recursively shred all files in a directory.
- Configurable pass count (default 3).

### `passgen` — Password & Passphrase Generation

- `generate_password(length, exclude)` — random password from character set.
- `generate_passphrase(words, separator)` — Diceware-style passphrase.
- `password_entropy(length)` / `passphrase_entropy(words)` — entropy calculation.
- Uses OS CSPRNG for all randomness.

### `shamir` — Shamir's Secret Sharing

- Split a secret into N shares with threshold T using GF(256) polynomial interpolation.
- `split(secret, shares, threshold)` — returns N share byte vectors.
- `combine(shares)` — reconstruct the original secret from ≥T shares.
- `encode_share(share)` / `decode_share(encoded)` — hex serialization.

### `stego` — Steganography

- LSB (Least Significant Bit) embedding into raw pixel data.
- `embed(image_data, message)` — embed message bytes into image pixels.
- `extract(stego_data)` — extract hidden message from stego image.
- `capacity(image_data)` — calculate maximum message size.

### `qr` — QR Code Key Exchange

- `hbzf-key://` URI scheme: `hbzf-key://<algorithm>/<fingerprint>?label=<name>`.
- `encode_key_uri(algorithm, fingerprint, label)` — generate URI string.
- `decode_key_uri(uri)` — parse URI into (algorithm, fingerprint, label).
- Used with QR code generators (e.g., segno) for visual key exchange.

### `error` — Error Types

`HbError` is a `thiserror::Error` enum covering all failure modes:
crypto failures, key not found, invalid passphrase, authentication failure,
I/O, serialization, contacts, and format errors.

`HbResult<T>` is the crate-wide `Result` alias.

---

## Python Layer

### PyO3 Bindings (`crates/python`)

- **55+ functions** and **6 classes** exposed via `hb_zayfer._native`.
- Heavy crypto (RSA keygen, KDF, encrypt/decrypt) releases the GIL via `py.detach()`.
- Key interchange formats: RSA/Ed25519 → PEM strings; X25519 → raw `bytes`; PGP → ASCII armor.
- Classes: `KeyStore`, `KeyMetadata`, `Contact`, `BackupManifest`, `AuditEntry`, `AuditLogger`.
- Type stubs in `_native.pyi` (PEP 561 compliant with `py.typed` marker).

### Public Python API (`python/hb_zayfer/__init__.py`)

Re-exports all `_native` symbols into the top-level `hb_zayfer` namespace.
`__version__` is dynamically set from the Rust library via `version()`.

**Function categories**: Symmetric encryption (AES, ChaCha20), KDF (Argon2id, scrypt),
RSA, Ed25519, X25519, OpenPGP, HBZF format, utilities, audit logging,
password generation, Shamir SSS, steganography, secure shredding, QR exchange.

### Click CLI (`python/hb_zayfer/cli.py`)

Entry point: `hb-zayfer`. Commands: `keygen`, `encrypt`, `decrypt`, `sign`,
`verify`, `encrypt-text`, `decrypt-text`. Sub-command groups: `keys` (list,
import, export, delete), `contacts` (list, add, remove, link), `backup`
(create, restore, verify), `audit` (show, verify, export). Uses `rich` for
colored output and status spinners.

### PySide6 GUI (`python/hb_zayfer/gui/`)

**Views (13):**

| Module | Purpose |
|--------|---------|
| `encrypt_view.py` | File/text encryption with algorithm and recipient selection |
| `decrypt_view.py` | File/text decryption with auto-detected wrapping mode |
| `keygen_view.py` | Key pair generation for all supported algorithms |
| `keyring_view.py` | Browse, search, sort, export, and delete stored keys |
| `contacts_view.py` | Manage contacts, link keys, import keys, edit details |
| `sign_view.py` | Sign files or messages with Ed25519, RSA, or PGP |
| `verify_view.py` | Verify signatures against public keys |
| `passgen_view.py` | Generate random passwords and passphrases |
| `messaging_view.py` | Secure end-to-end encrypted messaging |
| `qr_view.py` | QR code key exchange via `hbzf-key://` URIs |
| `settings_view.py` | Configure defaults, themes, KDF parameters, keystore path |
| `audit_view.py` | Browse audit log, verify integrity, export entries |
| `backup_view.py` | Create, verify, and restore encrypted keystore backups |

**Support Modules (11):**

| Module | Purpose |
|--------|---------|
| `app.py` | Application entry point, initializes `QApplication` |
| `main_window.py` | `QMainWindow` with sidebar navigation and `QStackedWidget` |
| `workers.py` | `QRunnable`-based workers dispatched to `QThreadPool` |
| `theme.py` | Light/dark theme support with `QPalette` configuration |
| `notifications.py` | Toast notification system for success/error/info feedback |
| `settings_manager.py` | Persistent GUI settings (geometry, theme, last-used options) |
| `statusbar.py` | Custom status bar with operation status and key count |
| `about_dialog.py` | About dialog showing version, author, and license info |
| `password_strength.py` | Real-time password strength meter with visual bar |
| `dragdrop.py` | Drag-and-drop file handling for encrypt/decrypt views |
| `clipboard.py` | Clipboard operations with auto-clear for sensitive data |

**Key GUI features:**

- Sidebar navigation with `Alt+1` through `Alt+9` keyboard shortcuts
- Toast notifications for operation feedback (with fade animation)
- Autocomplete recipient field from contacts
- Password strength meter with real-time visual assessment
- Drag-and-drop file input on encrypt and decrypt views
- Copy-to-clipboard with auto-clear for sensitive data
- Search and filter on keyring and contacts tables
- Column sorting on all data tables
- Context menu actions on keyring entries
- Dark/light theme switching (persisted in `gui_settings.json`)
- Window geometry and settings persistence across sessions

### FastAPI Web UI (`python/hb_zayfer/web/`)

**30 API routes** across these categories:

| Category | Endpoints |
|----------|-----------|
| Info | `GET /version` |
| Text encrypt/decrypt | `POST /encrypt/text`, `POST /decrypt/text` |
| File encrypt/decrypt | `POST /encrypt/file`, `POST /decrypt/file` |
| Key management | `POST /keygen`, `GET /keys`, `DELETE /keys/{fp}`, `GET /keys/{fp}/public` |
| Signing | `POST /sign`, `POST /verify` |
| Contacts | `GET /contacts`, `POST /contacts`, `DELETE /contacts/{name}`, `POST /contacts/link` |
| Audit | `GET /audit/recent`, `GET /audit/verify`, `GET /audit/count`, `POST /audit/export` |
| Backup | `POST /backup/create`, `POST /backup/verify`, `POST /backup/restore` |
| Config | `GET /config`, `GET /config/{key}`, `PUT /config/{key}` |
| Password gen | `POST /passgen` |
| Shamir SSS | `POST /shamir/split`, `POST /shamir/combine` |
| QR exchange | `POST /qr/encode`, `POST /qr/decode` |

- Static SPA served from `web/static/` (HTML + JS + CSS).
- Optional bearer-token auth via `HB_ZAYFER_API_TOKEN`.
- CORS restricted to localhost origins.

---

## WASM Module

The `crates/wasm/` crate provides a **standalone** WebAssembly build:

| Function | Description |
|----------|-------------|
| `aes_gcm_encrypt` | AES-256-GCM encrypt (returns nonce‖ciphertext+tag) |
| `aes_gcm_decrypt` | AES-256-GCM decrypt |
| `chacha20_encrypt` | ChaCha20-Poly1305 encrypt |
| `chacha20_decrypt` | ChaCha20-Poly1305 decrypt |
| `ed25519_keygen` | Generate Ed25519 keypair (returns JSON hex) |
| `ed25519_sign` | Sign with Ed25519 |
| `ed25519_verify` | Verify Ed25519 signature |
| `x25519_keygen` | Generate X25519 keypair (returns JSON hex) |
| `x25519_dh` | X25519 Diffie-Hellman shared secret |
| `derive_key` | Argon2id key derivation (password + salt → 32 bytes) |
| `sha256` | SHA-256 hash |
| `version` | Module version string |
| `random_bytes` | Generate n random bytes |

**Design decisions**: The WASM module is standalone (does not depend on
`hb_zayfer_core`) because Sequoia/OpenPGP and file I/O are incompatible
with `wasm32-unknown-unknown`. It reimplements core algorithms using
WASM-compatible pure-Rust crates.

```bash
# Build WASM module
./scripts/build-wasm.sh
# Outputs: pkg/ with .wasm + JS/TS bindings for web/nodejs/bundler targets
```

---

## Security Design Decisions

| Concern | Approach |
|---------|----------|
| Memory safety | Rust core; no `unsafe` in application code |
| Key material | `SecureBytes` wrapper with `zeroize` on drop for all secrets |
| Nonce reuse | Random 96-bit nonce per message; chunk nonce derived from base + index |
| Chunk reordering | Chunk index in AAD prevents reorder/truncation |
| Password hashing | Argon2id default (64 MiB memory, 3 iterations) |
| Side channels | `BlindedSigningKey` for RSA-PSS; timing-safe comparisons |
| File permissions | `0o700` / `0o600` on private key storage (Unix) |
| API auth | Optional bearer token for web interface |
| Audit trail | Tamper-evident HMAC hash chain for all sensitive operations |
| Backup security | Keystore backups encrypted with separate passphrase |
| Secure deletion | Multi-pass overwrite before unlinking sensitive files |
| Key constraints | Key usage restrictions and expiry tracking |
| Rate limiting | Configurable rate limiting on password-based operations |

---

## Data Flow: File Encryption

```
User provides: plaintext file, wrapping mode, passphrase or recipient

  1. [KDF / ECDH / RSA-OAEP]  →  32-byte symmetric key
  2. (Optional) Compress plaintext with flate2
  3. Generate random 12-byte base nonce
  4. Write HBZF header (magic, version, params, nonce, …)
  5. Read plaintext in configurable chunks (default 64 KiB)
     For each chunk i:
       a. Derive chunk nonce: base_nonce XOR (i as LE u64) in bytes 4..12
       b. AAD = [algo_id, wrapping_id] ++ chunk_index_LE
       c. AEAD encrypt chunk → ciphertext (chunk_size + 16 B tag)
       d. Write [4B chunk_len_LE][ciphertext]
  6. Flush output
  7. Log operation to audit trail
```

---

## Testing Strategy

| Suite | Count | Location |
|-------|-------|----------|
| Rust unit tests | 85 | `#[cfg(test)]` blocks in each module |
| Rust integration tests | 53 | `crates/core/tests/integration.rs` |
| Rust doc tests | 7 | Documentation examples |
| Python binding tests | 59 | `tests/python/test_crypto.py` |
| Web API tests | 34 | `tests/python/test_web.py` |
| **Total** | **238** | |

- **Benchmarks**: `crates/core/benches/crypto_benches.rs` — Criterion benchmarks
  for KDF (3 presets) and encrypt/decrypt (3 sizes × 4 operations).
- **CI**: GitHub Actions on Linux/macOS/Windows; Rust fmt+clippy+test, Python maturin+pytest.
