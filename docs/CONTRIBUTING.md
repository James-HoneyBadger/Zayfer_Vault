# Contributing Guide

Thank you for your interest in contributing to **HB Zayfer**! This guide
covers project setup, code standards, testing, and the pull-request workflow.

---

## Prerequisites

| Tool | Minimum Version | Purpose |
|------|----------------|---------|
| Rust | 1.75+ | Core library & CLI |
| Python | 3.10+ | Bindings, GUI, web, tests |
| Maturin | 1.0+ | Build Python ↔ Rust bridge |
| wasm-pack | 0.12+ | WASM build (optional) |
| Node.js | 18+ | WASM tests (optional) |

---

## Repository Layout

```
HB_Zayfer/
├── Cargo.toml                # Workspace root
├── pyproject.toml             # Maturin / Python packaging
├── crates/
│   ├── core/                  # hb_zayfer_core — 20 Rust modules
│   │   ├── src/
│   │   │   ├── lib.rs
│   │   │   ├── aes_gcm.rs        # AES-256-GCM
│   │   │   ├── chacha20.rs       # ChaCha20-Poly1305
│   │   │   ├── rsa.rs            # RSA-2048/4096
│   │   │   ├── ed25519.rs        # Ed25519 signatures
│   │   │   ├── x25519.rs         # X25519 key agreement
│   │   │   ├── openpgp.rs        # OpenPGP (Sequoia)
│   │   │   ├── kdf.rs            # Argon2id & scrypt
│   │   │   ├── format.rs         # HBZF container
│   │   │   ├── keystore.rs       # Key + contact storage
│   │   │   ├── audit.rs          # Audit logging
│   │   │   ├── backup.rs         # Backup/restore
│   │   │   ├── config.rs         # Configuration
│   │   │   ├── compression.rs    # Deflate layer
│   │   │   ├── secure_mem.rs     # mlock secure memory
│   │   │   ├── shred.rs          # Secure file shredding
│   │   │   ├── passgen.rs        # Password generation
│   │   │   ├── shamir.rs         # Shamir's Secret Sharing
│   │   │   ├── stego.rs          # LSB steganography
│   │   │   ├── qr.rs             # QR key exchange URIs
│   │   │   └── error.rs          # Error types
│   │   ├── tests/
│   │   │   └── integration.rs    # Integration tests
│   │   └── benches/
│   │       └── crypto_benches.rs
│   ├── cli/                   # hb_zayfer_cli — Clap CLI
│   │   └── src/main.rs
│   ├── python/                # hb_zayfer_python — PyO3 bindings
│   │   └── src/lib.rs
│   └── wasm/                  # hb_zayfer_wasm — wasm-bindgen
│       └── src/lib.rs
├── python/
│   └── hb_zayfer/             # Python package
│       ├── __init__.py
│       ├── _native.pyi        # Type stubs
│       ├── cli.py             # Click CLI
│       ├── gui/               # PySide6 desktop GUI (13 views)
│       └── web/               # FastAPI web server
├── scripts/
│   ├── build-wasm.sh          # WASM build script
│   └── package.sh             # Multi-platform packaging
├── tests/
│   └── python/
│       ├── test_crypto.py     # Cryptographic tests
│       └── test_web.py        # Web API tests
└── docs/                      # Documentation
```

---

## Development Setup

The quickest way:

```bash
git clone https://github.com/<owner>/HB_Zayfer.git
cd HB_Zayfer
./run.sh build    # Creates venv, installs deps, builds native extension
```

Or manually:

```bash
# 1. Clone
git clone https://github.com/<owner>/HB_Zayfer.git
cd HB_Zayfer

# 2. Create virtual environment
python -m venv .venv
source .venv/bin/activate

# 3. Install in development mode
pip install -e ".[all]"

# 4. Build the native extension
maturin develop --release -m crates/python/Cargo.toml

# 5. Verify
python -c "import hb_zayfer; print(hb_zayfer.version())"
```

---

## Code Standards

### Rust

- **Edition**: 2021
- **Formatting**: `cargo fmt` (default rustfmt config)
- **Linting**: `cargo clippy -- -D warnings`
- **Documentation**: All public items must have `///` doc comments
- **Error handling**: Return `HbResult<T>`, never `unwrap()` in library code
- **Unsafe**: No `unsafe` in the core crate

### Python

- **Type hints**: Required for all function signatures
- **Formatting**: PEP 8, enforced by the project style
- **Imports**: Standard → third-party → local, grouped with blank lines

---

## Testing

### Running Tests

```bash
# Rust unit + integration tests
cargo test --workspace

# Python tests
pytest tests/python/ -v

# Web API tests
pytest tests/python/test_web.py -v

# Benchmarks
cargo bench -p hb_zayfer_core
```

### Test Counts

| Suite | Count |
|-------|-------|
| Rust unit tests | ~85 |
| Rust integration tests | ~41 |
| Rust doc tests | ~7 |
| Python tests | ~42 |
| Web API tests | ~8 |
| **Total** | **~238** |

### Writing Tests

- **Rust**: Add `#[test]` functions in the same module or in `tests/integration.rs`
- **Python**: Add tests in `tests/python/test_crypto.py`
- **Web**: Add tests in `tests/python/test_web.py` (uses `TestClient` from Starlette)

Every new feature should include tests. Aim for:

- ✅ Happy path
- ✅ Error / edge cases
- ✅ Round-trip (encrypt → decrypt, sign → verify, split → combine)

---

## Adding a New Rust Module

1. Create `crates/core/src/newmodule.rs`
2. Add `pub mod newmodule;` to `crates/core/src/lib.rs`
3. Add public re-exports to `lib.rs` if needed
4. Write unit tests in `newmodule.rs` (`#[cfg(test)]`)
5. Add integration tests to `crates/core/tests/integration.rs`
6. Add Python bindings in `crates/python/src/lib.rs`
7. Add CLI commands in `crates/cli/src/main.rs`
8. Add web routes in `python/hb_zayfer/web/routes.py`
9. Update type stubs in `python/hb_zayfer/_native.pyi`
10. Update documentation

---

## Adding a GUI View

1. Create `python/hb_zayfer/gui/newview.py` with a `QWidget` subclass
2. Import in `main_window.py` and add to the sidebar list
3. Use `workers.py` for background crypto operations
4. Follow existing view patterns (form layout, status bar feedback)

---

## Pull Request Workflow

1. Fork the repository
2. Create a feature branch: `git checkout -b feat/my-feature`
3. Make your changes with tests
4. Run the full test suite: `cargo test --workspace && pytest tests/python/ -v`
5. Run lints: `cargo fmt --check && cargo clippy -- -D warnings`
6. Commit with a descriptive message
7. Open a pull request against `main`

### Commit Message Format

```
<type>: <short description>

<optional body>
```

Types: `feat`, `fix`, `docs`, `refactor`, `test`, `ci`, `chore`

---

## Release Checklist

1. Update version in `Cargo.toml` (workspace), `pyproject.toml`, and `CHANGELOG.md`
2. Run full test suite
3. Build wheels: `maturin build --release -m crates/python/Cargo.toml`
4. Build WASM: `./scripts/build-wasm.sh`
5. Build packages: `./scripts/package.sh`
6. Tag: `git tag v<version>`
7. Push tag and create GitHub release
