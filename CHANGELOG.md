# Changelog

All notable changes to Zayfer Vault will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [Unreleased]

### Added

- **Liveness and readiness probes.** New unauthenticated endpoints
  `/healthz` (returns plain `ok`, no I/O) and `/readyz` (returns `ready`
  only after the on-disk keystore opens cleanly, otherwise
  `503 Service Unavailable`). Designed for systemd `ExecStartPost`
  curls, Kubernetes `livenessProbe`/`readinessProbe`, and Docker
  `HEALTHCHECK` directives. The legacy JSON `/health` endpoint is
  unchanged.
- **Graceful shutdown** for `hb-zayfer serve`. Ctrl+C (and `SIGTERM` on
  Unix) now triggers a graceful drain: in-flight requests are allowed to
  complete for up to 10 seconds before the listener closes, instead of
  being torn down mid-response.
- **Structured request logging.** The web platform now installs a
  `tracing-subscriber` and a `tower-http::TraceLayer`, emitting per-request
  spans with method, path, status, and latency to stderr. The default filter
  is `hb_zayfer=info,tower_http=info`; override via the standard `RUST_LOG`
  environment variable.
- **Expanded WASM crypto surface.** The browser bindings now expose
  `sha512`, `hmac_sha256`, `hmac_sha512`, `hkdf_sha256`, and
  `random_password` (with character-class guarantees and modulo-bias-free
  rejection sampling), bringing parity with common operations available
  in the CLI/Python build.
- **Live audit log streaming.** New `GET /api/audit/stream` Server-Sent
  Events endpoint pushes new audit entries to connected clients in real
  time (2-second polling cadence, 15-second keep-alive). Each event has
  `event: audit` and a JSON payload matching `/api/audit/recent`.
- **TLS for the web platform.** New `--tls-cert <PATH>` and `--tls-key <PATH>`
  flags on `hb-zayfer serve` enable HTTPS via `axum-server` + rustls (ring
  provider, no C toolchain required). Mismatched flag pairs are rejected and
  the startup banner advertises `https://` URLs when TLS is active.
- **One-shot self-signed TLS.** New `--auto-tls` flag generates (and
  caches) a self-signed certificate under `~/.hb_zayfer/tls/` valid for
  `localhost`, `127.0.0.1`, `::1`, and the bind host. The private key is
  written with `0600` permissions. Intended for local development only;
  mutually exclusive with `--tls-cert`/`--tls-key`.
- **Web platform authentication.** The Rust-native web server now requires a
  bearer token by default. A fresh hex token is generated on each launch and
  printed in the startup banner (Jupyter-style); clients pass it via
  `Authorization: Bearer <token>` or the `?token=` query parameter. New CLI
  flags `--no-auth` (explicit opt-out for trusted loopback use) and
  `--token <value>` (use a fixed token) on `hb-zayfer serve`.
- New `hb_zayfer_core::aead` module providing a generic AEAD helper shared by
  `aes_gcm` and `chacha20`, eliminating ~340 LOC of duplicated streaming and
  nonce-derivation logic.
- `CryptoConfig` in `hb_zayfer.gui.settings_manager` — single source of truth
  for the on-disk crypto configuration (cipher, KDF parameters, clipboard
  timeout) with atomic writes.
- `ViewBase` mixin in `hb_zayfer.gui.base_view` providing shared notification,
  file-dialog, and worker helpers for incremental adoption by GUI views.
- Pre-commit configuration (`.pre-commit-config.yaml`) covering rustfmt,
  clippy, ruff, and end-of-file fixers.
- **Keygen rate limiting.** The web platform caps concurrent expensive
  keypair generations at 2 per process; excess requests receive
  `429 Too Many Requests` instead of starving the host CPU.
- **Path-traversal hardening.** Backup endpoints reject empty paths, NUL
  bytes, `..` components, and writes under `/etc`, `/proc`, `/sys`, `/dev`,
  `/boot`, `/root`, and `/var/log`. Covered by new unit and HTTP tests.
- **Passphrase resolution from stdin & environment.** The CLI now accepts
  `--passphrase-file -` (read passphrase from stdin) and falls back to the
  `ZAYFER_PASSPHRASE` environment variable before prompting interactively.
- 12 additional unit tests for the new `aead` module: nonce derivation
  uniqueness, AAD index reorder detection, chunk-index overflow, tampered
  ciphertext, mismatched AAD, and per-cipher error labelling.
- **New web API endpoints** for key lifecycle and audit:
  `PUT /api/keys/:fp/expiry` (set or clear an RFC 3339 expiry),
  `PUT /api/keys/:fp/usage` (constrain a key to specific usages),
  `GET /api/keys/expiring?days=N` (list expired and soon-to-expire keys),
  `POST /api/audit/export` (write the audit log to a validated path).
- **Typed Python exceptions** (subclassing the closest built-in for backward
  compatibility): `ZayferError`, `AuthenticationError`, `KeyNotFoundError`,
  `ContactNotFoundError`, `IntegrityError`, `KeyAlreadyExistsError`,
  `ContactAlreadyExistsError`. Re-exported from the top-level package.
- Refreshed `_native.pyi` stubs (PEP 604 unions, declared exception types).
- Python lint job in CI (`ruff check`, `ruff format --check`, `mypy`); Python
  3.10 added to the test matrix.
- README badges, "Why Zayfer Vault?" value-proposition section, and table of
  contents.

### Changed

- `aes_gcm` and `chacha20` are now thin facades over the generic AEAD helper;
  public function signatures and constants are unchanged.
- The duplicated `_load_kdf_settings` / `_load_default_cipher` /
  `_load_config` / `_save_config` helpers in `encrypt_view.py` and
  `settings_view.py` now delegate to the centralised `CryptoConfig`.
- Documentation: archived the March-2026 refactoring planning folder under
  `docs/archive/refactoring/` (status was 0% past its declared deadline);
  added an explicit branding note to the Rust API and Technical references
  clarifying that the `hb_zayfer` identifier is retained for compatibility.

### Security

- **Explicit request body limit** on the web platform: ~257 MiB
  (MAX_UPLOAD_BYTES + 1 MiB envelope headroom), enforced via axum's
  `DefaultBodyLimit`. Oversized requests are rejected with
  `413 Payload Too Large` before any handler runs.
- **HSTS over TLS.** When the platform is bound over HTTPS, every response
  now carries `Strict-Transport-Security: max-age=31536000; includeSubDomains`.
  HSTS is intentionally **not** sent over plaintext (per RFC 6797).
- **Defence-in-depth response headers** on every web platform reply:
  `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`,
  `Referrer-Policy: no-referrer`, `Cross-Origin-Opener-Policy: same-origin`,
  and a restrictive `Permissions-Policy` denying camera, microphone,
  geolocation, and FLoC.
- The web platform can now serve traffic over TLS, eliminating cleartext
  exposure of the bearer token and request bodies on hostile networks.
- Web platform endpoints under `/api/*` now refuse unauthenticated requests by
  default. `/health` remains exempt for liveness probes; static assets are
  unauthenticated so the SPA can load before sign-in. Token comparison uses
  constant-time equality.
- Backup-related endpoints reject path traversal (`..`), NUL-byte injection,
  and writes under sensitive system roots as defence-in-depth on top of OS
  permissions.
- Concurrent keypair-generation requests are bounded to prevent CPU
  exhaustion by an authenticated client.

### Deprecated

- The Python FastAPI backend (`hb_zayfer.web`) is deprecated in favour of the
  Rust-native platform server (`hb-zayfer serve`). Importing the module now
  emits a `DeprecationWarning`. The module remains available for backward
  compatibility and will be removed in a future release.

---



### Changed

- Consolidated the Rust-native platform runtime for CLI and browser workflows.
- Reorganized the documentation set into clearer guides, reference, and project sections.
- Refreshed GitHub repository metadata to match the current Rust-first product positioning.

### Improved

- Tightened release-readiness across docs, workspace structure, and repository presentation.

## [1.1.0] — 2026-04-18

### Added

- Added a polished Home dashboard and expanded secure messaging workflow for the desktop GUI.
- Expanded the browser UI to expose more of the platform’s encryption, key, and utility features.

### Changed

- Rebranded the user-facing application from HB Zayfer to Zayfer Vault while preserving internal compatibility.
- Refined launcher diagnostics and onboarding so setup and recovery are clearer on fresh installs.

### Improved

- Tightened documentation across the install, quickstart, maintenance, and technical reference guides.
- Cleaned up strict Rust lint issues and release verification so CI stays green across workspace targets.

## [1.0.1] — 2026-04-04

### Security

- Hardened the web API with safer filename sanitization and strict home-directory path validation for uploads, backups, and audit exports.
- Added constant-time audit integrity checks, nonce-space exhaustion guards for chunked encryption, and stronger KDF input validation in Python and WASM bindings.
- Improved RSA key-size detection during import to avoid heuristic misclassification.

### Improved

- Added optional `--compress` support to CLI encryption workflows.
- Kept the backup/restore GUI responsive with background workers, busy indicators, and cooperative cancellation.
- Refined onboarding, password-strength screening, launcher native-module detection, and notification stacking behavior.

### CI & Docs

- Expanded GitHub Actions coverage with GUI and web smoke tests, a WASM build job, and `cargo audit`.
- Added new maintenance and encryption/password hygiene documentation for end users.

## [1.0.0] — 2025-06-09

### Sprint 6 — Infrastructure & Distribution

- **QR Code Key Exchange** (`crates/core/src/qr.rs`):
  - `hbzf-key://` URI scheme for sharing public keys via QR codes.
  - `qr_encode_key_uri()` and `qr_decode_key_uri()` in Rust, Python, and CLI.
  - GUI **QR Exchange** view for generating and scanning key URIs.
  - Web API endpoints: `POST /qr/encode`, `POST /qr/decode`.

- **WebAssembly Module** (`crates/wasm/`):
  - Standalone `wasm-bindgen` crate for browser and Node.js environments.
  - 13 exported functions: `aes_gcm_encrypt/decrypt`, `chacha20_encrypt/decrypt`,
    `ed25519_keygen/sign/verify`, `x25519_keygen/dh`, `derive_key`, `sha256`,
    `version`, `random_bytes`.
  - Build script: `scripts/build-wasm.sh` (web/nodejs/bundler targets).

- **Cross-Platform Packaging** (`scripts/package.sh`):
  - Debian `.deb`, Fedora `.rpm`, Arch `PKGBUILD`.
  - Portable AppImage for Linux.
  - macOS `.app` bundle + DMG.
  - Python wheel via maturin.

### Sprint 5 — Advanced Cryptography

- **Shamir's Secret Sharing** (`crates/core/src/shamir.rs`):
  - Split secrets into N shares with configurable threshold T.
  - Reconstruct with any T-of-N shares using GF(256) polynomial interpolation.
  - CLI: `hb-zayfer shamir split`, `hb-zayfer shamir combine`.
  - Python: `shamir_split()`, `shamir_combine()` (hex-encoded shares).
  - Web API: `POST /shamir/split`, `POST /shamir/combine`.

- **Steganography** (`crates/core/src/stego.rs`):
  - LSB (Least Significant Bit) embedding into pixel data.
  - `stego_embed()`, `stego_extract()`, `stego_capacity()`.
  - Support for capacity checking before embedding.

- **Secure Messaging View** (`python/hb_zayfer/gui/messaging_view.py`):
  - GUI view for end-to-end encrypted message exchange.
  - Contact selection, message encryption/decryption in one interface.

### Sprint 4 — Security Features

- **Secure File Shredding** (`crates/core/src/shred.rs`):
  - Multi-pass overwrite (configurable passes) + unlink.
  - File and recursive directory shredding.
  - CLI: `hb-zayfer shred [--passes N] [--recursive]`.
  - Python: `shred_file()`, `shred_directory()`.

- **Password Generator** (`crates/core/src/passgen.rs`):
  - Random password generation with configurable length and character exclusions.
  - Diceware-style passphrase generation with configurable word count and separator.
  - Entropy calculation for passwords and passphrases.
  - CLI: `hb-zayfer passgen [--length N] [--words N] [--separator S] [--exclude CHARS]`.
  - Python: `generate_password()`, `generate_passphrase()`, `password_entropy()`, `passphrase_entropy()`.
  - Web API: `POST /passgen`.
  - GUI **PassGen** view with real-time entropy display.

- **Key Expiry Warnings**:
  - `KeyExpiryStatus` enum: `Valid`, `ExpiresSoon`, `Expired`.
  - Key metadata tracks expiry dates; CLI and GUI warn about expiring keys.

- **Multi-Recipient Encryption**:
  - HBZF format supports encrypting to multiple recipients in a single operation.
  - CLI and GUI support specifying multiple `--recipient` flags.

### Sprint 3 — Developer Experience & Features

- **Compression Support** (`crates/core/src/compression.rs`):
  - Optional flate2/deflate compression integrated into HBZF encryption pipeline.
  - Automatic decompression on decrypt when compression flag is set.

- **GUI Sign & Verify Views**:
  - `sign_view.py`: Sign files or messages with Ed25519, RSA, or PGP keys.
  - `verify_view.py`: Verify signatures with visual status feedback.

- **Batch Directory Encryption**:
  - CLI: `hb-zayfer encrypt-dir` and `hb-zayfer decrypt-dir`.
  - Recursively encrypt/decrypt all files in a directory tree.

- **Shell Completions**:
  - CLI: `hb-zayfer completions [bash|zsh|fish|elvish|powershell]`.
  - Generates shell-specific completion scripts via `clap_complete`.

- **JSON Output Mode**:
  - Global `--json` flag for machine-readable output.
  - Supported on `keys list`, `passgen`, `shamir`, `shred` commands.

- **Clipboard Auto-Clear** (`python/hb_zayfer/gui/clipboard.py`):
  - Sensitive data copied to clipboard is automatically cleared after a timeout.

### Sprint 2 — Interface Completeness

- **CLI Configuration Commands**:
  - `hb-zayfer config get/set/list/reset/path` for managing settings.

- **Passphrase File Support**:
  - `--passphrase-file` flag reads passphrase from a file (useful for scripting).

- **HBZF Inspect Command**:
  - `hb-zayfer inspect <file>`: displays HBZF header metadata
    (algorithm, KDF, wrapping mode, plaintext size).

- **GUI Audit Log Viewer** (`python/hb_zayfer/gui/audit_view.py`):
  - Browse audit entries, verify integrity, export logs from the GUI.

- **GUI Backup/Restore View** (`python/hb_zayfer/gui/backup_view.py`):
  - Create, verify, and restore keystore backups from the GUI.

- **Web File Encryption Endpoints**:
  - `POST /api/encrypt/file` and `POST /api/decrypt/file` for file upload encryption.

- **Web Audit, Backup & Config APIs**:
  - `GET /api/audit/recent`, `GET /api/audit/verify`, `GET /api/audit/count`, `POST /api/audit/export`.
  - `POST /api/backup/create`, `POST /api/backup/verify`, `POST /api/backup/restore`.
  - `GET /api/config`, `GET /api/config/{key}`, `PUT /api/config/{key}`.

### Sprint 1 — Security Hardening

- **Timing-Safe Authentication**:
  - Constant-time comparison for AEAD tag verification and API token checks.

- **Rate Limiting**:
  - Configurable rate limiting on password-based operations to slow brute-force.

- **Configurable Chunk Size**:
  - HBZF chunk size configurable (default 64 KiB) for performance tuning.

- **Secure Memory** (`crates/core/src/secure_mem.rs`):
  - `SecureBytes` wrapper with `Zeroize` + `ZeroizeOnDrop`.
  - Used for all key material and derived keys.

- **Compression Module** (`crates/core/src/compression.rs`):
  - Flate2/deflate compression with configurable level.
  - `compress()` / `decompress()` public API.

- **Audit HMAC Integrity**:
  - Audit log entries now include HMAC for tamper-evident chaining.

- **Key Usage Constraints**:
  - `KeyUsage` enum: `Signing`, `Encryption`, `KeyAgreement`, `Authentication`.
  - Keys can be restricted to specific operations.

### Desktop GUI — Professional UI Overhaul

- Dark and light theme system with runtime toggle (`theme.py`).
- Toast notification system with fade animations (`notifications.py`).
- Persistent settings manager — saves window geometry, theme, preferences (`settings_manager.py`).
- Custom status bar showing current view, item counts, and version (`statusbar.py`).
- About dialog with dynamic version display (`about_dialog.py`).
- Password strength meter with real-time feedback (`password_strength.py`).
- Drag-and-drop file selection for encrypt and decrypt views (`dragdrop.py`).
- Audit utilities for viewing security logs (`audit_utils.py`).
- Background worker system using `QRunnable` / `QThreadPool` (`workers.py`).

- **Encrypt View Enhancements**: Recipient autocomplete, copy-to-clipboard,
  default cipher from settings, PGP User ID field visibility.
- **Decrypt View**: Copy-to-clipboard, auto-detect wrapping mode.
- **Key Gen**: Passphrase confirmation, show/hide toggle, strength meter.
- **Keyring**: Search/filter, column sorting, right-click context menus, import.
- **Contacts**: Search/filter, edit contacts, right-click menus.
- **Settings**: Default algorithm persistence, keystore path, theme.

### Keyboard Shortcuts

- `Ctrl+Q` — Quit application.
- `Alt+1` through `Alt+9` — Navigate to sidebar views.
- `Ctrl+F` — Focus search box in Keyring or Contacts view.
- `Ctrl+R` — Refresh current view.

### Changed

- Worker threads migrated from `QThread` to `QRunnable` / `QThreadPool`.
- Sidebar styling with grouped visual sections and responsive hover/selection.
- Window title dynamically includes version number.

### Fixed

- Double-delete crash in keyring view.
- Version in About dialog reads dynamically from Rust core.
- Toast notification positioning uses global coordinates.
- Theme stylesheet caching to avoid redundant recompilation.
- Drag-and-drop stylesheet deduplication.

### Removed

- Unused `DragDropZone` widget class.
- Dead `__main__` blocks in GUI modules.
- Unused imports and signals across GUI codebase.

---

## [0.1.0] — 2025-03-06

### Added

- **Rust core library** (`hb_zayfer_core`):
  - AES-256-GCM symmetric encryption with streaming chunk support.
  - ChaCha20-Poly1305 symmetric encryption with streaming chunk support.
  - RSA-2048/4096 key generation, OAEP encryption, PSS signing.
  - Ed25519 key generation, signing, and verification.
  - X25519 ECDH key agreement with HKDF-SHA256 derivation.
  - OpenPGP certificate generation, encrypt/decrypt, sign/verify (via Sequoia).
  - Argon2id and scrypt password-based key derivation.
  - HBZF streaming file encryption format (v1) with 64 KiB chunks.
  - On-disk keystore with encrypted private keys (v2 envelope).
  - Contact management with key association.
  - Unified error types (`HbError`).

- **Rust CLI** (`hb_zayfer_cli`):
  - `keygen`, `encrypt`, `decrypt`, `sign`, `verify` commands.
  - `keys list/export/import/delete` subcommands.
  - `contacts list/add/remove` subcommands.
  - Progress bars and interactive passphrase prompts.

- **Python bindings** (PyO3):
  - Full exposure of all core operations as `hb_zayfer._native`.
  - GIL-releasing for heavy crypto operations.
  - PEP 561 type stubs (`_native.pyi` + `py.typed`).

- **Python CLI** (Click + Rich):
  - `hb-zayfer` entry point with all commands.
  - Colored output, status spinners, table formatting.

- **Desktop GUI** (PySide6):
  - Six-view sidebar: Encrypt, Decrypt, Key Gen, Keyring, Contacts, Settings.
  - Threaded workers for responsive UI.

- **Web interface** (FastAPI + vanilla JS):
  - REST API for text encrypt/decrypt, keygen, sign/verify, keys, contacts.
  - Static SPA frontend.
  - Optional bearer-token authentication.
  - CORS restricted to localhost.

- **Testing**:
  - 31 Rust integration tests.
  - Comprehensive Python binding tests (`test_crypto.py`).
  - FastAPI route tests (`test_web.py`).

- **CI** (GitHub Actions):
  - Multi-platform Rust builds (Linux, macOS, Windows).
  - Python test matrix (3.11 + 3.12).

- **Documentation**:
  - Full documentation suite (architecture, API reference, CLI, web/GUI,
    security model, HBZF format spec, contributing guide).
