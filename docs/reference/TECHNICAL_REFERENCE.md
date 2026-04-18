# Technical Reference

Compact reference for the **current** Zayfer Vault runtime layout and command surface.

---

## Runtime summary

| Interface | Recommended launch path | Notes |
|-----------|-------------------------|-------|
| Desktop GUI | `./run.sh gui` | PySide6 shell backed by the Rust native extension |
| Web platform | `./run.sh web` | Rust-native browser server |
| CLI | `./run.sh cli ...` | Primary supported command line surface |
| Python API | `import hb_zayfer` | Compatibility bindings into the Rust core |

---

## Core algorithms

| Primitive | Current implementation |
|-----------|------------------------|
| Symmetric encryption | AES-256-GCM, ChaCha20-Poly1305 |
| Password KDFs | Argon2id, scrypt |
| Signatures | Ed25519, RSA-PSS, OpenPGP |
| Key agreement | X25519 |
| Secret sharing | Shamir |
| Container format | HBZF |

---

## CLI quick reference

### Key commands

```bash
./run.sh cli keygen --algorithm ed25519 --label my-key
./run.sh cli encrypt --input file.txt --output file.txt.hbzf --password
./run.sh cli decrypt --input file.txt.hbzf --output file.txt
./run.sh cli sign --input file.txt --key <fingerprint> --output file.txt.sig
./run.sh cli verify --input file.txt --signature file.txt.sig --key <fingerprint>
```

### Management commands

```bash
./run.sh cli keys list
./run.sh cli contacts add Alice --email alice@example.com
./run.sh cli backup create --output backup.hbzf
./run.sh cli audit show --limit 20
./run.sh cli config list
./run.sh cli status --json
./run.sh cli serve --port 8000
```

### Utility commands

```bash
./run.sh cli inspect sample.hbzf
./run.sh cli encrypt-dir --input ./plain --output ./encrypted
./run.sh cli decrypt-dir --input ./encrypted --output ./restored
./run.sh cli passgen --length 24
./run.sh cli shamir split "master secret" --shares 5 --threshold 3
./run.sh cli shred ./secrets.txt --passes 3
```

---

## Important flags

| Command | Required flags |
|---------|----------------|
| `keygen` | `--algorithm`, `--label` |
| `encrypt` | `--input`, `--output` |
| `decrypt` | `--input`, `--output` |
| `sign` | `--input`, `--key`, `--output` |
| `verify` | `--input`, `--signature`, `--key` |
| `backup create` | `--output` |
| `backup restore` / `verify` | `--input` |

---

## Web routes in the Rust-native server

| Route group | Endpoints |
|-------------|-----------|
| Health | `/health`, `/api/version`, `/api/status` |
| Text crypto | `/api/encrypt/text`, `/api/decrypt/text` |
| File crypto | `/api/encrypt/file`, `/api/decrypt/file` |
| Keys | `/api/keygen`, `/api/keys`, `/api/keys/{fingerprint}/public` |
| Contacts | `/api/contacts`, `/api/contacts/link` |
| Signatures | `/api/sign`, `/api/verify` |
| Audit | `/api/audit/count`, `/api/audit/recent`, `/api/audit/verify` |
| Backup | `/api/backup/create`, `/api/backup/verify`, `/api/backup/restore` |
| Config | `/api/config`, `/api/config/{key}` |
| Utilities | `/api/passgen` |

---

## Environment variables

| Variable | Scope |
|----------|-------|
| `HB_ZAYFER_HOME` | Shared data directory override for all runtimes |
| `HB_ZAYFER_SKIP_ONBOARDING` | GUI/CI convenience flag |
| `HB_ZAYFER_PORT` | Python compatibility web app only |
| `HB_ZAYFER_API_TOKEN` | Python compatibility web app only |
| `HB_ZAYFER_RATE_LIMIT` / `HB_ZAYFER_RATE_WINDOW` | Python compatibility web app only |

---

## Default data layout

| Path | Purpose |
|------|---------|
| `~/.hb_zayfer/keyring.json` | Key metadata index |
| `~/.hb_zayfer/contacts.json` | Contact store |
| `~/.hb_zayfer/audit.log` | Tamper-evident audit chain |
| `~/.hb_zayfer/config.toml` | Core runtime configuration |
| `~/.hb_zayfer/gui_settings.json` | Desktop UI preferences |

---

## Operational checks

```bash
./run.sh doctor
./run.sh cli --help
./run.sh web
./run.sh gui
HB_ZAYFER_SKIP_ONBOARDING=1 QT_QPA_PLATFORM=offscreen ./run.sh test
```

See [HBZF_FORMAT.md](HBZF_FORMAT.md) for the binary container details and [CLI.md](CLI.md) for the full command guide.
