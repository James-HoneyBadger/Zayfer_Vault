# Contributing Guide

Thank you for your interest in contributing to **Zayfer Vault**! This guide
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

```text
HB_Zayfer/
├── crates/
│   ├── core/      # Rust crypto, storage, audit, backup, config, shared services
│   ├── cli/       # Rust CLI plus the Rust-native web server
│   ├── python/    # PyO3 bridge for Python consumers and the desktop GUI
│   └── wasm/      # Browser/Node WebAssembly target
├── python/
│   └── hb_zayfer/
│       ├── gui/   # PySide6 desktop compatibility shell
│       ├── web/   # Browser assets and Python compatibility backend
│       └── __init__.py
├── tests/
│   └── python/    # Python and web compatibility regression tests
├── scripts/       # Packaging and WASM helpers
└── docs/          # Documentation
```

The current product direction is **Rust-first**: launcher, CLI, and web runtime are centered in the Rust workspace, while Python remains for bindings and the desktop shell.

---

## Development Setup

The quickest way:

```bash
git clone https://github.com/<owner>/Zayfer_Vault.git
cd Zayfer_Vault
./run.sh build    # Creates venv, installs deps, builds native extension
```

Or manually:

```bash
# 1. Clone
git clone https://github.com/<owner>/Zayfer_Vault.git
cd Zayfer_Vault

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

### Test Coverage Areas

| Area | Command |
|------|---------|
| Rust workspace checks | `cargo test --workspace` |
| Python compatibility tests | `pytest tests/python/ -v` |
| Headless smoke suite | `HB_ZAYFER_SKIP_ONBOARDING=1 QT_QPA_PLATFORM=offscreen ./run.sh test` |

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
8. If the feature is browser-facing, add or update routes in `crates/cli/src/platform_server.rs`
9. Update Python bindings or stubs in `crates/python/src/lib.rs` and `python/hb_zayfer/_native.pyi` as needed
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
4. Run the full verification set: `cargo test --workspace && pytest tests/python/ -v`
5. Run lints: `cargo fmt --check && cargo clippy --workspace --all-targets -- -D warnings`
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
