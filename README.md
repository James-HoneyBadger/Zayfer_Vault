# Zayfer Vault — Encryption / Decryption Suite

[![CI](https://github.com/James-HoneyBadger/Zayfer_Vault/actions/workflows/ci.yml/badge.svg)](https://github.com/James-HoneyBadger/Zayfer_Vault/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/)
[![Rust](https://img.shields.io/badge/rust-stable-orange.svg)](https://www.rust-lang.org/)
[![Platforms](https://img.shields.io/badge/platforms-linux%20%7C%20macOS%20%7C%20windows-lightgrey.svg)](#)

A full-featured cryptographic toolkit with a **Rust core**, **Rust-native platform runtime**,
**Python bindings**, **WebAssembly module**, and multiple user interfaces: **Rust CLI**,
**desktop GUI** (PySide6 compatibility shell), **browser-based web UI**, and a **WASM-powered web target**.

**Version 1.1.1** — Zayfer Vault by James Temple / Honey Badger Universe

---

## Why Zayfer Vault?

- **One toolbox, every surface.** Rust core powers a CLI, desktop GUI, web UI, and WASM target — same primitives, same on-disk format, no impedance mismatch.
- **Modern, audited primitives.** AES-256-GCM, ChaCha20-Poly1305, Ed25519, X25519, RSA, Argon2id, scrypt — implemented with `RustCrypto` and `sequoia-openpgp`.
- **Authenticated streaming format (HBZF).** Chunked, integrity-protected, optionally compressed; suitable for multi-gigabyte files.
- **Batteries included.** Encrypted keystore, contacts, audit trail, encrypted backups, password generation, Shamir secret sharing, secure shred, QR helpers, steganography.
- **OpenPGP interop** out of the box for talking to existing GPG users.
- **Memory hygiene.** Secrets zeroized on drop; mlock on Unix.

---

## Table of Contents

- [Features](#features)
- [Architecture](#architecture)
- [Quick Start](#quick-start)
- [Usage](#usage)
- [HBZF File Format](#hbzf-file-format)
- [Test Suite](#test-suite)
- [Documentation](#documentation)
- [WASM Module](#wasm-module)
- [Cross-Platform Packaging](#cross-platform-packaging)
- [License](#license)

---

## Features

| Category | Algorithms / Capabilities |
|---|---|
| **Symmetric** | AES-256-GCM, ChaCha20-Poly1305 |
| **Asymmetric** | RSA-2048/4096, Ed25519, X25519 |
| **OpenPGP** | Key generation, encrypt/decrypt, sign/verify |
| **KDF** | Argon2id, scrypt |
| **File format** | HBZF authenticated streaming container with optional compression |
| **Key management** | Encrypted keystore, contacts, audit trail, encrypted backups |
| **Utilities** | Password generation, Shamir SSS, secure shredding, QR helpers, steganography |
| **Interfaces** | Rust CLI, Rust-native web platform, PySide6 desktop GUI, Python bindings, WASM target |

---

## Architecture

Zayfer Vault is now **Rust-first**:

- `crates/core` contains the cryptographic engine, storage, config, audit, and shared services.
- `crates/cli` provides the primary CLI and the Rust-native web server.
- `crates/python` exposes the PyO3 compatibility bridge for the desktop GUI and Python consumers.
- `crates/wasm` builds the browser/Node-compatible WebAssembly target.

Compatibility identifiers such as `hb_zayfer` and `HB_ZAYFER_*` remain in place for existing users and scripts.

---

## Quick Start

> **📖 For detailed setup and troubleshooting, see [INSTALL.md](INSTALL.md)**

```bash
git clone https://github.com/James-HoneyBadger/Zayfer_Vault.git
cd Zayfer_Vault
./run.sh doctor
./run.sh gui
./run.sh web
./run.sh cli --help
```

### Linux desktop dependencies

```bash
sudo apt-get update
sudo apt-get install -y pkg-config libssl-dev nettle-dev build-essential python3-venv libxcb-cursor0
```

### Manual development setup

```bash
python -m venv .venv
source .venv/bin/activate
pip install --upgrade pip maturin
pip install -e ".[all]"
maturin develop --release -m crates/python/Cargo.toml
```

---

## Usage

### Desktop GUI

```bash
./run.sh gui
```

The desktop app is a PySide6 shell backed by the native Rust extension.
It includes workflows for encryption, decryption, key management, contacts,
signing, verification, audit, backup, and settings.

### Rust CLI

```bash
# Generate a key
./run.sh cli keygen --algorithm ed25519 --label my-key

# Encrypt and decrypt
./run.sh cli encrypt --input secret.txt --output secret.txt.hbzf --password
./run.sh cli decrypt --input secret.txt.hbzf --output secret.txt

# Sign and verify
./run.sh cli sign --input document.pdf --key <fingerprint> --output document.pdf.sig
./run.sh cli verify --input document.pdf --signature document.pdf.sig --key <fingerprint>

# Utilities
./run.sh cli passgen --length 24
./run.sh cli audit show --limit 10
./run.sh cli backup create --output backup.hbzf
```

### Browser platform

```bash
./run.sh web
# or
./run.sh cli serve --host 127.0.0.1 --port 8000
```

### Python API

```python
import hb_zayfer as hbz

key = hbz.derive_key_argon2(b"passphrase", hbz.generate_salt())
nonce, ct = hbz.aes_encrypt(key, b"Hello, World!", b"")
pt = hbz.aes_decrypt(key, nonce, ct, b"")
```

The Python package remains available for scripting and GUI integration, but the primary runtime path is Rust.
```
---

## Project Layout

```text
Zayfer_Vault/
├── crates/
│   ├── core/      # Rust cryptography, storage, audit, config, shared services
│   ├── cli/       # Rust CLI and the Rust-native web server
│   ├── python/    # PyO3 bridge for Python and GUI integration
│   └── wasm/      # WebAssembly target
├── python/
│   └── hb_zayfer/
│       ├── gui/   # PySide6 desktop shell
│       ├── web/   # Browser assets and compatibility backend code
│       └── __init__.py
├── scripts/       # Build and packaging helpers
├── tests/         # Rust and Python regression tests
└── docs/          # User, developer, and operational guides
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

> See [docs/reference/HBZF_FORMAT.md](docs/reference/HBZF_FORMAT.md) for the full binary format specification.

---

## Test Suite

Zayfer Vault is validated with both Rust and Python regression suites.
The recommended verification command is:

```bash
cargo test --workspace
pytest tests/python/ -v
```

For CI-style GUI smoke checks:

```bash
HB_ZAYFER_SKIP_ONBOARDING=1 QT_QPA_PLATFORM=offscreen ./run.sh test
```

---

## Documentation

### 📚 Complete Documentation Suite

| Guide | Description | Audience |
|-------|-------------|----------|
| **[INSTALL.md](INSTALL.md)** | Complete installation guide (Rust, Python, WASM, troubleshooting) | All users |
| **[docs/guides/QUICKSTART.md](docs/guides/QUICKSTART.md)** | 10-minute quick start tutorial | New users |
| **[docs/guides/USER_GUIDE.md](docs/guides/USER_GUIDE.md)** | Comprehensive user manual | End users |
| **[docs/guides/SECURE_COMMUNICATIONS.md](docs/guides/SECURE_COMMUNICATIONS.md)** | Encryption and decryption practices tutorial | Security-conscious users |
| **[docs/reference/CLI.md](docs/reference/CLI.md)** | Current Rust CLI reference and examples | CLI users |
| **[docs/guides/WEB_GUI.md](docs/guides/WEB_GUI.md)** | Desktop GUI and Rust-native web platform guide | GUI and browser users |
| **[docs/reference/PYTHON_API.md](docs/reference/PYTHON_API.md)** | Python compatibility bindings and API reference | Developers |
| **[docs/reference/RUST_API.md](docs/reference/RUST_API.md)** | Rust core API reference | Rust developers |
| **[docs/project/ARCHITECTURE.md](docs/project/ARCHITECTURE.md)** | Workspace and runtime architecture overview | Developers |
| **[docs/reference/SECURITY.md](docs/reference/SECURITY.md)** | Security model and threat analysis | Security teams |
| **[docs/reference/HBZF_FORMAT.md](docs/reference/HBZF_FORMAT.md)** | Binary file format specification | Implementers |
| **[docs/reference/TECHNICAL_REFERENCE.md](docs/reference/TECHNICAL_REFERENCE.md)** | Technical reference and API quick reference | Developers |
| **[docs/project/CONTRIBUTING.md](docs/project/CONTRIBUTING.md)** | Development and contribution guide | Contributors |

### 🎯 Quick Links

**New to Zayfer Vault?** Start here:
1. [Install](INSTALL.md) → 2. [Quick Start](docs/guides/QUICKSTART.md) → 3. [User Guide](docs/guides/USER_GUIDE.md)

**Want secure communications?** Follow the tutorial:
- [Secure Communications](docs/guides/SECURE_COMMUNICATIONS.md) — Key exchange, verification, and best practices

**Need API reference?**
- Python: [PYTHON_API.md](docs/reference/PYTHON_API.md) | Rust: [RUST_API.md](docs/reference/RUST_API.md) | CLI: [CLI.md](docs/reference/CLI.md) | WASM: [docs/project/ARCHITECTURE.md](docs/project/ARCHITECTURE.md#wasm-module)

---

## WASM Module

The `crates/wasm/` crate provides a standalone WebAssembly build for browser
and Node.js environments. It exposes 13 functions: AES-GCM, ChaCha20, Ed25519,
X25519, Argon2id KDF, SHA-256, and secure random bytes.

```bash
# Build WASM module
./scripts/build-wasm.sh
```

> See [docs/project/ARCHITECTURE.md](docs/project/ARCHITECTURE.md) for WASM API details.

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
