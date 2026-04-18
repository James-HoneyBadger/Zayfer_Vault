# Zayfer Vault Documentation

This documentation set reflects the **current Rust-first configuration** of Zayfer Vault.
Use the launcher for the supported paths:

- `./run.sh gui` — desktop GUI
- `./run.sh web` — Rust-native browser platform
- `./run.sh cli ...` — Rust CLI

> Product branding is **Zayfer Vault**, while compatibility names such as `hb_zayfer` and `HB_ZAYFER_*` remain in package imports and environment variables.

---

## Guides

| Document | Description |
|----------|-------------|
| [Quick Start](guides/QUICKSTART.md) | Install and launch the GUI, web app, or CLI in a few minutes |
| [Installation](../INSTALL.md) | Platform setup, dependencies, and troubleshooting |
| [User Guide](guides/USER_GUIDE.md) | Day-to-day usage across encryption, keys, backup, and audit |
| [Tutorial: Encryption, Decryption & Passwords](guides/TUTORIAL_ENCRYPTION_PASSWORDS.md) | Guided hands-on walkthrough |
| [Maintenance](guides/MAINTENANCE.md) | Upgrade, recovery, and operational checks |
| [Secure Communications](guides/SECURE_COMMUNICATIONS.md) | Practical encryption and signing guide |

## Reference

| Document | Description |
|----------|-------------|
| [CLI Reference](reference/CLI.md) | Current Rust CLI commands and examples |
| [Web & GUI](guides/WEB_GUI.md) | PySide6 desktop GUI and Rust-native web platform |
| [Python API](reference/PYTHON_API.md) | PyO3-backed Python bindings and compatibility layer |
| [Rust API](reference/RUST_API.md) | Core library modules and public Rust APIs |
| [HBZF Format](reference/HBZF_FORMAT.md) | Container format details |
| [Security](reference/SECURITY.md) | Threat model, security properties, and operational cautions |
| [Technical Reference](reference/TECHNICAL_REFERENCE.md) | Quick command and configuration cheat sheet |

## Project Information

| Document | Description |
|----------|-------------|
| [Architecture](project/ARCHITECTURE.md) | Workspace layout, runtime boundaries, and data flow |
| [Contributing](project/CONTRIBUTING.md) | Development workflow and contribution setup |
| [Changelog](../CHANGELOG.md) | Release history |
| [Refactoring Notes](refactoring/README.md) | Long-form architectural planning and progress |
