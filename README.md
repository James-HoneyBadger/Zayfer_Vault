# HB Zayfer — Encryption / Decryption Suite

A full‑featured cryptographic toolkit with **Rust core**, **Python bindings**,
and three user interfaces: **CLI**, **desktop GUI** (PySide6), and a **browser‑based
web UI** (FastAPI + vanilla JS).

---

## Features

| Category | Algorithms / Capabilities |
|---|---|
| **Symmetric** | AES-256-GCM, ChaCha20-Poly1305 |
| **Asymmetric** | RSA-2048/4096 (OAEP + PSS), Ed25519, X25519 (ECDH) |
| **OpenPGP** | PGP key generation, encrypt, decrypt, sign, verify (via Sequoia) |
| **KDF** | Argon2id, scrypt |
| **File format** | HBZF streaming AEAD with 64 KiB chunks |
| **Key management** | Encrypted keystore, contacts, key association |
| **Interfaces** | Rust CLI, Python CLI (Click), PySide6 GUI, FastAPI web |

---

## Architecture

```
┌──────────── User Interfaces ────────────┐
│                                         │
│   CLI (Rust)     CLI (Python / Click)   │
│   GUI (PySide6)  Web (FastAPI + JS)     │
│                                         │
├────────── Python Bindings (PyO3) ───────┤
│                                         │
│            hb_zayfer._native            │
│                                         │
├──────────── Rust Core Library ──────────┤
│                                         │
│       hb_zayfer_core (RustCrypto)       │
│                                         │
└─────────────────────────────────────────┘
```

---

## Quick Start

### Prerequisites

- **Rust** ≥ 1.75 (stable)
- **Python** ≥ 3.10
- **System libs** (Linux): `pkg-config libssl-dev nettle-dev`
- [**Maturin**](https://github.com/PyO3/maturin): `pip install maturin`

### Build the native module

```bash
# Development build (editable)
maturin develop --release

# Or build a wheel
maturin build --release
```

### Install Python extras

```bash
pip install -e ".[all]"        # CLI + GUI + Web + dev
# Or pick individual extras:
pip install -e ".[cli]"        # Click CLI only
pip install -e ".[gui]"        # + PySide6 desktop
pip install -e ".[web]"        # + FastAPI web server
pip install -e ".[dev]"        # + pytest, httpx
```

### Rust CLI

```bash
cargo run --bin hb_zayfer_cli -- --help
```

---

## Usage

### Python CLI

```bash
# Generate an Ed25519 key pair
hb-zayfer keygen --algorithm ed25519 --label my-key

# Encrypt a file
hb-zayfer encrypt --input secret.txt --output secret.hbzf

# Decrypt a file
hb-zayfer decrypt --input secret.hbzf --output recovered.txt

# Sign a file
hb-zayfer sign --input document.pdf --key-fingerprint <fp>

# List stored keys
hb-zayfer keys list
```

### Desktop GUI

```bash
hb-zayfer-gui
```

### Web Interface

```bash
hb-zayfer-web          # opens http://127.0.0.1:8000
```

### Python API

```python
import hb_zayfer as hbz

# Symmetric encryption
key = hbz.derive_key_argon2(b"passphrase", hbz.generate_salt())
ct  = hbz.aes_encrypt(key, b"Hello, World!")
pt  = hbz.aes_decrypt(key, ct)

# RSA
priv_pem, pub_pem = hbz.rsa_generate(2048)
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

# KeyStore
ks = hbz.KeyStore()
ks.store_public_key(fp, pub_bytes, "ed25519", "my-key")
keys = ks.list_keys()
```

---

## Project Layout

```
HB_Zayfer/
├── Cargo.toml                 # Workspace root
├── pyproject.toml              # Python/Maturin config
├── crates/
│   ├── core/                   # hb_zayfer_core (Rust crypto library)
│   │   ├── src/
│   │   │   ├── lib.rs
│   │   │   ├── aes_gcm.rs     # AES-256-GCM
│   │   │   ├── chacha20.rs    # ChaCha20-Poly1305
│   │   │   ├── rsa.rs         # RSA encrypt/sign
│   │   │   ├── ed25519.rs     # Ed25519 signatures
│   │   │   ├── x25519.rs      # X25519 ECDH
│   │   │   ├── openpgp.rs     # OpenPGP (Sequoia)
│   │   │   ├── kdf.rs         # Argon2id / scrypt
│   │   │   ├── format.rs      # HBZF streaming AEAD
│   │   │   ├── keystore.rs    # Key / contact storage
│   │   │   └── error.rs       # Error types
│   │   └── tests/
│   │       └── integration.rs # 31 integration tests
│   ├── cli/                    # Rust CLI (clap)
│   └── python/                 # PyO3 bindings (cdylib)
├── python/
│   └── hb_zayfer/
│       ├── __init__.py         # Public API
│       ├── _native.pyi         # Type stubs (PEP 561)
│       ├── cli.py              # Click CLI
│       ├── gui/                # PySide6 desktop app
│       │   ├── main_window.py
│       │   ├── encrypt_view.py
│       │   ├── decrypt_view.py
│       │   ├── keygen_view.py
│       │   ├── keyring_view.py
│       │   ├── contacts_view.py
│       │   └── settings_view.py
│       └── web/                # FastAPI web app
│           ├── app.py
│           ├── routes.py
│           └── static/
│               ├── index.html
│               ├── style.css
│               └── app.js
├── tests/
│   └── python/
│       ├── test_crypto.py      # Python binding tests
│       └── test_web.py         # FastAPI route tests
└── .github/
    └── workflows/
        └── ci.yml              # GitHub Actions CI
```

---

## HBZF File Format

The custom **HBZF** (HB Zayfer Format) uses authenticated streaming encryption:

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

---

## Testing

```bash
# Rust tests (31 integration tests)
cargo test --workspace

# Python tests (requires: maturin develop)
pytest tests/python/ -v
```

---

## CI

GitHub Actions runs on every push / PR to `main`:

- **Rust job**: `fmt --check` → `clippy` → `cargo test` → `cargo build --release`
  (Linux, macOS, Windows)
- **Python job**: `maturin develop --release` → `pytest`
  (Linux + macOS, Python 3.11 + 3.12)

---

## Key Storage

Keys are stored under `~/.hb_zayfer/` (override with `HB_ZAYFER_HOME`):

```
~/.hb_zayfer/
├── keys/
│   ├── private/      # AES-256-GCM encrypted (Argon2id passphrase)
│   └── public/
├── keyring.json      # Key metadata index
└── contacts.json     # Contact ↔ key associations
```

---

## License

MIT
