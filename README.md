# Zayfer Vault — Encryption / Decryption Suite

A full-featured cryptographic toolkit with a **Rust core**, **Python bindings**,
**WebAssembly module**, and four user interfaces: **CLI**, **desktop GUI** (PySide6),
**browser-based web UI** (FastAPI + vanilla JS), and a **WASM-powered web target**.

**Version 1.0.1** — Zayfer Vault by James Temple / Honey Badger Universe

---

## Features

| Category | Algorithms / Capabilities |
|---|---|
| **Symmetric** | AES-256-GCM, ChaCha20-Poly1305 |
| **Asymmetric** | RSA-2048/4096 (OAEP + PSS), Ed25519, X25519 (ECDH) |
| **OpenPGP** | PGP key generation, encrypt, decrypt, sign, verify (via Sequoia) |
| **KDF** | Argon2id, scrypt |
| **File format** | HBZF streaming AEAD with configurable chunks, optional compression |
| **Key management** | Encrypted keystore, contacts, key usage constraints, key expiry warnings |
| **Shamir SSS** | Split secrets into shares, reconstruct with threshold |
| **Steganography** | LSB image embedding and extraction |
| **Secure shredding** | Multi-pass file/directory overwrite and deletion |
| **Password generation** | Random passwords and Diceware-style passphrases with entropy scoring |
| **QR key exchange** | `hbzf-key://` URI scheme for key sharing via QR codes |
| **Audit** | Tamper-evident audit log with HMAC integrity verification |
| **Compression** | Optional flate2 compression before encryption |
| **Secure memory** | Zeroize-on-drop `SecureBytes` for sensitive data |
| **WASM** | Browser-ready cryptographic module (AES, ChaCha20, Ed25519, X25519, Argon2) |
| **Packaging** | Cross-platform packaging (deb, rpm, Arch, AppImage, macOS, wheel) |
| **Interfaces** | Rust CLI, Python CLI (Click), PySide6 GUI (14 views), FastAPI web, WASM |

---

## Architecture

```
┌──────────────── User Interfaces ─────────────────┐
│                                                   │
│   CLI (Rust)        CLI (Python / Click)          │
│   GUI (PySide6)     Web (FastAPI + JS)            │
│                                                   │
├──────────── Python Bindings (PyO3) ──────────────┤
│                                                   │
│              hb_zayfer._native                    │
│                                                   │
├───────────── Rust Core Library ──────────────────┤
│                                                   │
│         hb_zayfer_core (RustCrypto)               │
│         20 modules — see below                    │
│                                                   │
├──────────── WASM Module (standalone) ────────────┤
│                                                   │
│  hb_zayfer_wasm (wasm-bindgen, browser-ready)     │
│                                                   │
└───────────────────────────────────────────────────┘
```

---

## Quick Start

> **📖 For detailed installation instructions, see [INSTALL.md](INSTALL.md)**

### One-Command Launch

```bash
git clone https://github.com/James-HoneyBadger/Zayfer_Vault.git
cd Zayfer_Vault
./run.sh              # Creates venv, installs deps, builds, launches GUI
./run.sh web          # Web server
./run.sh cli --help   # CLI commands
./run.sh test         # Run test suite
```

### Manual Setup

**Prerequisites:** Rust ≥ 1.75 · Python ≥ 3.10 · System libs (Linux): `pkg-config libssl-dev nettle-dev`

```bash
python -m venv .venv
source .venv/bin/activate
pip install maturin
pip install -e ".[all]"
maturin develop --release -m crates/python/Cargo.toml

# Verify installation
python -c "import hb_zayfer; print(f'Zayfer Vault v{hb_zayfer.version()}')"
```

---

## Usage

### Desktop GUI

```bash
hb-zayfer-gui
```

The GUI provides a sidebar with fourteen views:

| View | Shortcut | Description |
|------|----------|-------------|
| 🏠 **Home** | — | Overview dashboard with counts, quick actions, and first-step guidance |
| 🔐 **Encrypt** | `Alt+1` | File/text encryption with algorithm & recipient selection, drag-and-drop |
| 🔓 **Decrypt** | `Alt+2` | File/text decryption with auto-detected wrapping mode |
| 🔑 **Key Gen** | `Alt+3` | Generate key pairs (RSA, Ed25519, X25519, PGP) with strength meter |
| 📦 **Keyring** | `Alt+4` | Browse, search, sort, import/export, and delete stored keys |
| 👥 **Contacts** | `Alt+5` | Manage contacts and key associations with search and edit |
| ✍️ **Sign** | `Alt+6` | Sign files or messages with Ed25519, RSA, or PGP keys |
| ✅ **Verify** | `Alt+7` | Verify signatures against public keys |
| 🔒 **PassGen** | `Alt+8` | Generate random passwords and passphrases with entropy display |
| 💬 **Messaging** | `Alt+9` | Secure end-to-end encrypted messaging |
| 📱 **QR Exchange** | — | Share public keys via QR-code URIs (`hbzf-key://`) |
| ⚙️ **Settings** | — | Default algorithm, theme, keystore path, preferences |
| 📋 **Audit Log** | — | Browse and verify the tamper-evident audit trail |
| 💾 **Backup** | — | Create, verify, and restore encrypted keystore backups |

**Keyboard shortcuts**: `Ctrl+Q` quit, `Alt+1`–`Alt+9` navigate views, `Ctrl+F` search, `Ctrl+R` refresh.

### CLI

```bash
# Generate an Ed25519 key pair
hb-zayfer keygen ed25519 --label my-key

# Encrypt a file with a password
hb-zayfer encrypt secret.txt -p

# Encrypt a file for a recipient
hb-zayfer encrypt secret.txt --recipient alice

# Decrypt a file
hb-zayfer decrypt secret.txt.hbzf

# Sign and verify
hb-zayfer sign document.pdf --key <fingerprint-prefix>
hb-zayfer verify document.pdf document.pdf.sig --key <fingerprint-prefix>

# Batch encrypt/decrypt entire directories
hb-zayfer encrypt-dir ./documents -p
hb-zayfer decrypt-dir ./documents

# Inspect HBZF file metadata
hb-zayfer inspect secret.txt.hbzf

# Generate passwords and passphrases
hb-zayfer passgen --length 24
hb-zayfer passgen --words 6

# Shamir's Secret Sharing
hb-zayfer shamir split --shares 5 --threshold 3 --secret "master key"
hb-zayfer shamir combine --shares <hex1>,<hex2>,<hex3>

# Secure file shredding
hb-zayfer shred secret.txt --passes 3
hb-zayfer shred ./temp-dir --recursive

# Configuration management
hb-zayfer config list
hb-zayfer config set default_algorithm chacha

# Generate shell completions
hb-zayfer completions bash > ~/.local/share/bash-completion/completions/hb-zayfer

# JSON output mode for scripting
hb-zayfer keys list --json
hb-zayfer passgen --json
```

### Rust CLI

```bash
cargo run --bin hb-zayfer -- --help
```

### Web Interface

```bash
hb-zayfer-web          # opens http://127.0.0.1:8000
```

**30 REST API endpoints** including encrypt/decrypt files, keygen, sign/verify,
key management, contacts, audit, backup, config, password generation, Shamir
SSS, and QR key exchange.

### Python API

```python
import hb_zayfer as hbz

# Symmetric encryption (AES-256-GCM)
key = hbz.derive_key_argon2(b"passphrase", hbz.generate_salt())
nonce, ct = hbz.aes_encrypt(key, b"Hello, World!", b"")
pt = hbz.aes_decrypt(key, nonce, ct, b"")

# RSA key pair
priv_pem, pub_pem = hbz.rsa_generate(4096)
ct = hbz.rsa_encrypt(pub_pem, b"secret")
pt = hbz.rsa_decrypt(priv_pem, ct)

# Ed25519 signing
sk, vk = hbz.ed25519_generate()
sig = hbz.ed25519_sign(sk, b"message")
assert hbz.ed25519_verify(vk, b"message", sig)

# HBZF file format
hbz.encrypt_file("in.txt", "out.hbzf",
                  algorithm="aes", wrapping="password",
                  passphrase=b"secret")
hbz.decrypt_file("out.hbzf", "recovered.txt", passphrase=b"secret")

# Password generation
pw = hbz.generate_password(length=24, exclude="0O1l")
phrase = hbz.generate_passphrase(words=6, separator="-")

# Shamir's Secret Sharing
shares = hbz.shamir_split(b"secret", 5, 3)  # 5 shares, threshold 3
recovered = hbz.shamir_combine(shares[:3])

# Steganography
hbz.stego_embed(image_bytes, b"hidden message")
message = hbz.stego_extract(stego_image_bytes)

# Secure shredding
hbz.shred_file("/path/to/secret.txt", passes=3)

# QR key exchange
uri = hbz.qr_encode_key_uri("ed25519", "abc123", "Alice")
algo, fp, label = hbz.qr_decode_key_uri(uri)

# KeyStore & Contacts
ks = hbz.KeyStore()
keys = ks.list_keys()
ks.add_contact("Alice", email="alice@example.com")
```

---

## Project Layout

```
Zayfer_Vault/
├── Cargo.toml                 # Workspace root (version defined here)
├── pyproject.toml              # Python/Maturin config
├── CHANGELOG.md                # Release history
├── INSTALL.md                  # Installation guide
├── crates/
│   ├── core/                   # hb_zayfer_core (Rust crypto library)
│   │   ├── src/
│   │   │   ├── lib.rs          # Public API re-exports (20 modules)
│   │   │   ├── aes_gcm.rs     # AES-256-GCM
│   │   │   ├── chacha20.rs    # ChaCha20-Poly1305
│   │   │   ├── rsa.rs         # RSA encrypt/sign
│   │   │   ├── ed25519.rs     # Ed25519 signatures
│   │   │   ├── x25519.rs      # X25519 ECDH
│   │   │   ├── openpgp.rs     # OpenPGP (Sequoia)
│   │   │   ├── kdf.rs         # Argon2id / scrypt
│   │   │   ├── format.rs      # HBZF streaming AEAD
│   │   │   ├── keystore.rs    # Key / contact storage
│   │   │   ├── backup.rs      # Encrypted backup/restore
│   │   │   ├── audit.rs       # Audit logging (HMAC chain)
│   │   │   ├── config.rs      # Configuration
│   │   │   ├── compression.rs # Flate2 compression
│   │   │   ├── secure_mem.rs  # SecureBytes (zeroize-on-drop)
│   │   │   ├── shred.rs       # Secure file shredding
│   │   │   ├── passgen.rs     # Password/passphrase generation
│   │   │   ├── shamir.rs      # Shamir's Secret Sharing
│   │   │   ├── stego.rs       # Steganography (LSB)
│   │   │   ├── qr.rs          # QR code key exchange URIs
│   │   │   └── error.rs       # Error types
│   │   ├── benches/
│   │   │   └── crypto_benches.rs
│   │   └── tests/
│   │       └── integration.rs # 41 integration tests
│   ├── cli/                    # Rust CLI (clap) — 20+ commands
│   ├── python/                 # PyO3 bindings (cdylib) — 55+ functions
│   └── wasm/                   # WASM module (wasm-bindgen) — 13 functions
├── python/
│   └── hb_zayfer/
│       ├── __init__.py         # Public Python API (55+ functions, 6 classes)
│       ├── _native.pyi         # Type stubs (PEP 561)
│       ├── py.typed            # PEP 561 marker
│       ├── cli.py              # Click CLI
│       ├── gui/                # PySide6 desktop app (14 views + 11 support modules)
│       │   ├── app.py              # Application entry point
│       │   ├── main_window.py      # Main window + sidebar (14 views)
│       │   ├── encrypt_view.py     # Encrypt view
│       │   ├── decrypt_view.py     # Decrypt view
│       │   ├── keygen_view.py      # Key generation view
│       │   ├── keyring_view.py     # Keyring management
│       │   ├── contacts_view.py    # Contact management
│       │   ├── sign_view.py        # Digital signature view
│       │   ├── verify_view.py      # Signature verification view
│       │   ├── passgen_view.py     # Password generator view
│       │   ├── messaging_view.py   # Secure messaging view
│       │   ├── qr_view.py          # QR code key exchange view
│       │   ├── settings_view.py    # Settings view
│       │   ├── audit_view.py       # Audit log viewer
│       │   ├── backup_view.py      # Backup/restore view
│       │   ├── theme.py            # Dark/light theme system
│       │   ├── clipboard.py        # Clipboard with auto-clear
│       │   ├── notifications.py    # Toast notification system
│       │   ├── settings_manager.py # Persistent settings (JSON)
│       │   ├── statusbar.py        # Custom status bar
│       │   ├── about_dialog.py     # About dialog
│       │   ├── password_strength.py# Password strength meter
│       │   ├── dragdrop.py         # Drag-and-drop support
│       │   ├── audit_utils.py      # Audit log helpers
│       │   └── workers.py          # QRunnable background workers
│       └── web/                # FastAPI web app (30 API routes)
│           ├── app.py              # ASGI application
│           ├── routes.py           # API endpoints
│           └── static/             # SPA frontend (HTML/JS/CSS)
├── scripts/
│   ├── build-wasm.sh          # WASM build script (web/nodejs/bundler)
│   └── package.sh             # Cross-platform packaging
├── tests/
│   └── python/
│       ├── test_crypto.py      # 42 Python binding tests
│       └── test_web.py         # 8 FastAPI route tests
└── docs/                       # Documentation suite (14 guides)
```

---

## HBZF File Format

The custom **HBZF** (Zayfer Vault Format) uses authenticated streaming encryption:

| Offset | Field | Size |
|--------|-------|------|
| 0 | Magic `HBZF` | 4 B |
| 4 | Version | 1 B |
| 5 | Symmetric algorithm ID | 1 B |
| 6 | KDF algorithm ID | 1 B |
| 7 | Key wrapping mode | 1 B |
| 8+ | KDF params, salt, wrapped key, nonce | variable |
| … | Encrypted chunks (64 KiB each) | variable |

Key wrapping modes: **Password** (KDF → symmetric key), **RSA-OAEP**, **X25519-ECDH**.

> See [docs/HBZF_FORMAT.md](docs/HBZF_FORMAT.md) for the full binary format specification.

---

## Test Suite

| Suite | Count | Location |
|-------|-------|----------|
| Rust unit tests | 85 | `#[cfg(test)]` blocks in each module |
| Rust integration tests | 41 | `crates/core/tests/integration.rs` |
| Rust doc tests | 7 | Documentation examples |
| Python binding tests | 42 | `tests/python/test_crypto.py` |
| Web API tests | 8 | `tests/python/test_web.py` |
| **Total** | **183** | |

```bash
# Run all tests
cargo test --workspace && pytest tests/python/ -v
```

---

## Documentation

### 📚 Complete Documentation Suite

| Guide | Description | Audience |
|-------|-------------|----------|
| **[INSTALL.md](INSTALL.md)** | Complete installation guide (Rust, Python, WASM, troubleshooting) | All users |
| **[docs/QUICKSTART.md](docs/QUICKSTART.md)** | 10-minute quick start tutorial | New users |
| **[docs/USER_GUIDE.md](docs/USER_GUIDE.md)** | Comprehensive user manual | End users |
| **[docs/SECURE_COMMUNICATIONS.md](docs/SECURE_COMMUNICATIONS.md)** | Encryption and decryption practices tutorial | Security-conscious users |
| **[docs/CLI.md](docs/CLI.md)** | Complete CLI reference (20+ commands) | CLI users |
| **[docs/WEB_GUI.md](docs/WEB_GUI.md)** | Desktop GUI (14 views) and web interface guide | GUI users |
| **[docs/PYTHON_API.md](docs/PYTHON_API.md)** | Python API reference (55+ functions, 6 classes) | Developers |
| **[docs/RUST_API.md](docs/RUST_API.md)** | Rust API reference (20 modules) | Rust developers |
| **[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)** | System architecture overview | Developers |
| **[docs/SECURITY.md](docs/SECURITY.md)** | Security model and threat analysis | Security teams |
| **[docs/HBZF_FORMAT.md](docs/HBZF_FORMAT.md)** | Binary file format specification | Implementers |
| **[docs/TECHNICAL_REFERENCE.md](docs/TECHNICAL_REFERENCE.md)** | Technical reference and API quick reference | Developers |
| **[docs/CONTRIBUTING.md](docs/CONTRIBUTING.md)** | Development and contribution guide | Contributors |

### 🎯 Quick Links

**New to Zayfer Vault?** Start here:
1. [Install](INSTALL.md) → 2. [Quick Start](docs/QUICKSTART.md) → 3. [User Guide](docs/USER_GUIDE.md)

**Want secure communications?** Follow the tutorial:
- [Secure Communications](docs/SECURE_COMMUNICATIONS.md) — Key exchange, verification, and best practices

**Need API reference?**
- Python: [PYTHON_API.md](docs/PYTHON_API.md) | Rust: [RUST_API.md](docs/RUST_API.md) | CLI: [CLI.md](docs/CLI.md) | WASM: [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md#wasm-module)

---

## WASM Module

The `crates/wasm/` crate provides a standalone WebAssembly build for browser
and Node.js environments. It exposes 13 functions: AES-GCM, ChaCha20, Ed25519,
X25519, Argon2id KDF, SHA-256, and secure random bytes.

```bash
# Build WASM module
./scripts/build-wasm.sh
```

> See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for WASM API details.

---

## Cross-Platform Packaging

```bash
# Build platform packages
./scripts/package.sh deb       # Debian/Ubuntu .deb
./scripts/package.sh rpm       # Fedora/RHEL .rpm
./scripts/package.sh arch      # Arch PKGBUILD
./scripts/package.sh appimage  # Portable AppImage
./scripts/package.sh macos     # macOS .app + DMG
./scripts/package.sh wheel     # Python wheel
```

---

## License

Created by **James Temple** — Honey Badger Universe.
