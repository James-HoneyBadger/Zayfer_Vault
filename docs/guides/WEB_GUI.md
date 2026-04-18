# Web & Desktop GUI Reference

This guide reflects the **current runtime split** in Zayfer Vault v1.1.0:

- **Desktop GUI**: PySide6 application backed by the native Rust extension
- **Web platform**: browser UI served by the **Rust-native** `serve` command
- **Python web app**: retained as a compatibility and testing path

---

## Desktop GUI

### Launch

```bash
./run.sh gui

# Alternative compatibility launch
python -m hb_zayfer.gui
```

### Linux note

If the GUI fails to appear on Linux, install the missing Qt/XCB dependency first:

```bash
sudo apt-get install -y libxcb-cursor0
```

### Main views

| View | Purpose |
|------|---------|
| Home | Workspace summary and quick actions |
| Encrypt / Decrypt | File and text workflows |
| Key Gen / Keyring | Create, browse, export, and delete keys |
| Contacts | Manage recipients and metadata |
| Sign / Verify | Detached signature workflows |
| PassGen | Password and passphrase generation |
| Messaging / QR | Sharing and exchange helpers |
| Settings | Cipher, KDF, clipboard, theme, and UI preferences |
| Audit / Backup | Integrity checks and disaster recovery |

The GUI remains the best fit for desktop-first usage, while heavy crypto still runs in Rust underneath.

---

## Rust-native Web Platform

### Launch

```bash
./run.sh web

# Equivalent direct form
./run.sh cli serve --host 127.0.0.1 --port 8000
```

This serves the browser dashboard at `http://127.0.0.1:8000/`.
The frontend assets still live under `python/hb_zayfer/web/static/`, but the recommended server path is now Rust.

### Current browser-facing routes

| Area | Routes |
|------|--------|
| Health and status | `GET /health`, `GET /api/version`, `GET /api/status` |
| Keys | `GET /api/keys`, `DELETE /api/keys/{fingerprint}`, `GET /api/keys/{fingerprint}/public`, `POST /api/keygen` |
| Contacts | `GET /api/contacts`, `POST /api/contacts`, `DELETE /api/contacts/{name}`, `POST /api/contacts/link` |
| Text crypto | `POST /api/encrypt/text`, `POST /api/decrypt/text` |
| File crypto | `POST /api/encrypt/file`, `POST /api/decrypt/file` |
| Signatures | `POST /api/sign`, `POST /api/verify` |
| Backup | `POST /api/backup/create`, `POST /api/backup/verify`, `POST /api/backup/restore` |
| Audit | `GET /api/audit/count`, `GET /api/audit/recent`, `GET /api/audit/verify` |
| Config and passgen | `GET /api/config`, `PUT /api/config/{key}`, `POST /api/passgen` |

> The current Rust-native server does **not** expose Swagger or Redoc pages.

---

## Python Compatibility Web App

The repository still includes the older Python web backend for compatibility, tests, and development:

```bash
python -m hb_zayfer.web
```

When using that compatibility path directly, these environment variables are supported:

| Variable | Meaning |
|----------|---------|
| `HB_ZAYFER_HOME` | Shared app data directory override |
| `HB_ZAYFER_PORT` | Default port for the Python compatibility server |
| `HB_ZAYFER_API_TOKEN` | Optional bearer token requirement |
| `HB_ZAYFER_RATE_LIMIT` / `HB_ZAYFER_RATE_WINDOW` | Optional rate limiting for the Python backend |

---

## Quick API Examples

### Encrypt text

```bash
curl -X POST http://127.0.0.1:8000/api/encrypt/text \
  -H "Content-Type: application/json" \
  -d '{"plaintext":"hello","passphrase":"secret","algorithm":"aes256gcm"}'
```

### Generate a key

```bash
curl -X POST http://127.0.0.1:8000/api/keygen \
  -H "Content-Type: application/json" \
  -d '{"algorithm":"ed25519","label":"my-key"}'
```

### Show recent audit entries

```bash
curl http://127.0.0.1:8000/api/audit/recent?limit=10
```
