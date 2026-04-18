# Web & Desktop GUI Reference

**Zayfer Vault v1.0.1**

Zayfer Vault provides two graphical interfaces:

- **Desktop GUI** — PySide6 (Qt 6) native application with 13 sidebar views
- **Web GUI** — FastAPI server with 30 REST API endpoints and a
  browser-based dashboard (static HTML/JS/CSS)

---

## Desktop GUI

### Launching

```bash
# Via CLI entry point
hb-zayfer-gui

# Via Python module
python -m hb_zayfer.gui

# Direct launch
python python/hb_zayfer/gui/app.py
```

### Views (14)

| # | View | Icon | Shortcut | Description |
|---|------|------|----------|-------------|
| 1 | Home | 🏠 | — | Overview dashboard with quick actions, counts, and onboarding guidance |
| 2 | Encrypt | 🔐 | Alt+1 | Encrypt files or text (AES/ChaCha, password/RSA/X25519 wrapping) |
| 3 | Decrypt | 🔓 | Alt+2 | Decrypt `.hbzf` files or text blobs |
| 4 | Key Gen | 🔑 | Alt+3 | Generate RSA, Ed25519, X25519, and OpenPGP key pairs |
| 5 | Keyring | 📦 | Alt+4 | Browse, search, import, export, and delete stored keys |
| 6 | Contacts | 👥 | Alt+5 | Manage contacts and link public keys |
| 7 | Sign | ✍️ | Alt+6 | Sign files or messages with Ed25519, RSA-PSS, or PGP |
| 8 | Verify | ✔️ | Alt+7 | Verify signatures against stored or pasted public keys |
| 9 | PassGen | 🔐 | Alt+8 | Random password & diceware passphrase generator with entropy meter |
| 10 | Messaging | 💬 | Alt+9 | End-to-end encrypted message composition & reading |
| 11 | QR Exchange | 📱 | — | Encode/scan `hbzf-key://` URIs for contactless key exchange |
| 12 | Settings | ⚙️ | — | Theme, font size, default algorithm, KDF preset, confirm-shred toggle |
| 13 | Audit Log | 📋 | Alt+0 | Browse, verify, and export the tamper-evident audit trail |
| 14 | Backup | 💾 | — | Create, verify, and restore encrypted keystore backups |

### Source Files

| File | Purpose |
|------|---------|
| `gui/app.py` | Application entry point and `QApplication` setup |
| `gui/main_window.py` | Main window, sidebar, stacked widget, keyboard shortcuts |
| `gui/encrypt_view.py` | Encrypt view |
| `gui/decrypt_view.py` | Decrypt view |
| `gui/keygen_view.py` | Key generation view |
| `gui/keyring_view.py` | Keyring management view |
| `gui/contacts_view.py` | Contacts view |
| `gui/password_strength.py` | Password entropy bar widget |
| `gui/settings_view.py` | Settings/preferences view |
| `gui/audit_utils.py` | Audit log helpers and formatters |
| `gui/dragdrop.py` | Drag-and-drop file handling |
| `gui/workers.py` | `QThread` workers for long-running crypto ops |
| `gui/theme.py` | Dark/light/auto theme definitions |

### GUI Features

- **Drag & Drop** — Drop files onto Encrypt/Decrypt views to populate paths
- **Background Workers** — All cryptographic operations run in `QThread`
  workers so the UI remains responsive
- **Password Strength Meter** — Real-time entropy bar with strength labels
- **Dark / Light / Auto Themes** — Switch in Settings or auto-detect OS
- **Keyboard Shortcuts** — Alt+1 through Alt+9 and Alt+0 for quick navigation

---

## Web GUI

### Launching

```bash
# Via CLI
hb-zayfer-web              # starts on http://127.0.0.1:8000
hb-zayfer-web --port 9000  # custom port

# Via Python module
python -m hb_zayfer.web

# Via uvicorn
uvicorn hb_zayfer.web.app:app --reload
```

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `HB_ZAYFER_API_TOKEN` | *(unset)* | Bearer token for API authentication. When set, all requests must include `Authorization: Bearer <token>`. |
| `HB_ZAYFER_RATE_LIMIT` | `60` | Maximum requests per client IP per window. |
| `HB_ZAYFER_RATE_WINDOW` | `60` | Rate-limit window duration in seconds. |
| `HB_ZAYFER_PORT` | `8000` | Default port for the web server (overridden by `--port`). |
| `HB_ZAYFER_HOME` | `~/.hb_zayfer` | Data directory for keys, contacts, audit logs, and config. |

### Dashboard

The web server serves a single-page dashboard at `/` with:

- Home overview with version, key/contact counts, and quick actions
- Encrypt / Decrypt forms for both text and file upload/download workflows
- Key generation panel
- Key list with export/delete
- Contact management
- Sign / verify tools
- Password and passphrase generator
- Audit log viewer and integrity check
- Backup create, verify, and restore controls
- Settings editor for common defaults
- Interactive API docs at `/docs` (Swagger UI) and `/redoc`

### Static Assets

Static files are served from `python/hb_zayfer/web/static/`:

| File | Purpose |
|------|---------|
| `style.css` | Dashboard CSS |
| `app.js` | Frontend JS (fetch-based API calls) |

---

## REST API Reference

Base path: `/api`

### General

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/api/version` | Library version |

### Encryption & Decryption

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/api/encrypt/text` | Encrypt text (JSON body) |
| `POST` | `/api/decrypt/text` | Decrypt text (JSON body) |
| `POST` | `/api/encrypt/file` | Encrypt uploaded file (multipart) |
| `POST` | `/api/decrypt/file` | Decrypt uploaded file (multipart) |

### Key Management

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/api/keygen` | Generate key pair |
| `GET` | `/api/keys` | List all keys |
| `DELETE` | `/api/keys/{fingerprint}` | Delete a key |
| `GET` | `/api/keys/{fingerprint}/public` | Export public key |

### Contacts

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/api/contacts` | List contacts |
| `POST` | `/api/contacts` | Add contact |
| `DELETE` | `/api/contacts/{name}` | Remove contact |
| `POST` | `/api/contacts/link` | Link key to contact |

### Signing & Verification

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/api/sign` | Sign a message |
| `POST` | `/api/verify` | Verify a signature |

### Audit Log

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/api/audit/recent` | Recent entries (query: `?limit=50`) |
| `GET` | `/api/audit/verify` | Verify hash-chain integrity |
| `GET` | `/api/audit/count` | Total entry count |
| `POST` | `/api/audit/export` | Export log (query: `?destination=path`) |

### Backup

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/api/backup/create` | Create encrypted backup |
| `POST` | `/api/backup/verify` | Verify backup integrity |
| `POST` | `/api/backup/restore` | Restore from backup |

### Configuration

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/api/config` | Get full configuration |
| `GET` | `/api/config/{key}` | Get a single setting |
| `PUT` | `/api/config/{key}` | Update a setting |

### Password Generation

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/api/passgen` | Generate password or passphrase |

### Shamir's Secret Sharing

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/api/shamir/split` | Split secret into shares |
| `POST` | `/api/shamir/combine` | Reconstruct from shares |

### QR Key Exchange

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/api/qr/encode` | Encode public key as `hbzf-key://` URI |
| `POST` | `/api/qr/decode` | Decode `hbzf-key://` URI |

---

## API Examples

### Encrypt Text

```bash
curl -X POST http://127.0.0.1:8000/api/encrypt/text \
  -H "Content-Type: application/json" \
  -d '{"plaintext": "Hello!", "passphrase": "s3cret", "algorithm": "aes"}'
```

### Generate Key

```bash
curl -X POST http://127.0.0.1:8000/api/keygen \
  -H "Content-Type: application/json" \
  -d '{"algorithm": "ed25519", "label": "my-key"}'
```

### Encrypt File (multipart)

```bash
curl -X POST http://127.0.0.1:8000/api/encrypt/file \
  -F "file=@document.pdf" \
  -F "passphrase=s3cret" \
  -F "algorithm=chacha" \
  --output document.pdf.hbzf
```

### Generate Password

```bash
curl -X POST http://127.0.0.1:8000/api/passgen \
  -H "Content-Type: application/json" \
  -d '{"length": 24, "exclude": "0O1lI"}'
```

### Split Secret (Shamir)

```bash
curl -X POST http://127.0.0.1:8000/api/shamir/split \
  -H "Content-Type: application/json" \
  -d '{"secret": "bXktc2VjcmV0", "shares": 5, "threshold": 3}'
```

### Audit Log

```bash
# Recent 10 entries
curl http://127.0.0.1:8000/api/audit/recent?limit=10

# Verify integrity
curl http://127.0.0.1:8000/api/audit/verify
```
