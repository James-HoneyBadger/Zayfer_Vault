# CLI Reference

This page documents the **current Rust CLI** shipped with Zayfer Vault v1.1.1.
It matches the launcher paths used by the project today:

```bash
./run.sh cli <command> [options]
hb-zayfer <command> [options]
cargo run --bin hb-zayfer -- <command> [options]
```

> The repository still contains Python compatibility packaging, but the supported day-to-day CLI is the Rust binary above.

---

## Global Option

```bash
--json    Output results as JSON where supported
```

---

## Main Commands

| Command | Purpose |
|---------|---------|
| `keygen` | Generate a new key pair |
| `encrypt` / `decrypt` | Encrypt or decrypt files and streams |
| `sign` / `verify` | Create or verify detached signatures |
| `keys` | List, import, export, and delete keys |
| `contacts` | List, add, and remove contacts |
| `backup` | Create, verify, and restore encrypted backups |
| `audit` | Show, verify, and export the audit trail |
| `config` | Inspect and change runtime configuration |
| `status` | Show platform and workspace summary |
| `serve` | Start the Rust-native web platform |
| `inspect` | Read HBZF metadata without decrypting |
| `encrypt-dir` / `decrypt-dir` | Batch process directories |
| `completions` | Generate shell completions |
| `shred` | Securely overwrite and delete files |
| `passgen` | Generate passwords or passphrases |
| `shamir` | Split or reconstruct a secret |

---

## Common Examples

### Generate a key

```bash
./run.sh cli keygen --algorithm ed25519 --label "My Signing Key"
./run.sh cli keygen --algorithm x25519 --label "My Encryption Key"
```

Optional non-interactive passphrase:

```bash
./run.sh cli keygen --algorithm rsa4096 --label server-key --passphrase "change-me"
```

### Encrypt and decrypt a file

```bash
./run.sh cli encrypt --input secret.txt --output secret.txt.hbzf --password
./run.sh cli decrypt --input secret.txt.hbzf --output secret.txt
```

Recipient mode and compression:

```bash
./run.sh cli encrypt \
  --input report.pdf \
  --output report.pdf.hbzf \
  --recipient alice \
  --algorithm chacha20 \
  --compress
```

### Sign and verify

```bash
./run.sh cli sign --input document.pdf --key <fingerprint> --output document.pdf.sig
./run.sh cli verify --input document.pdf --signature document.pdf.sig --key <fingerprint>
```

### Inspect stored keys and contacts

```bash
./run.sh cli keys list
./run.sh cli keys export <fingerprint> --output public.pem
./run.sh cli keys import ./public.pem --label "Alice" --algorithm ed25519

./run.sh cli contacts add Alice --email alice@example.com
./run.sh cli contacts list
./run.sh cli contacts remove Alice
```

### Backup, audit, and config

```bash
./run.sh cli backup create --output ~/.hb_zayfer/backup.hbzf --label nightly
./run.sh cli backup verify --input ~/.hb_zayfer/backup.hbzf
./run.sh cli audit show --limit 20
./run.sh cli audit verify
./run.sh cli config list
./run.sh cli config set cipher ChaCha20-Poly1305
./run.sh cli config path
```

### Status and web server

```bash
./run.sh cli status --json
./run.sh cli serve --host 127.0.0.1 --port 8000
```

### Utility commands

```bash
./run.sh cli inspect vault.hbzf
./run.sh cli encrypt-dir --input ./docs --output ./docs.enc
./run.sh cli decrypt-dir --input ./docs.enc --output ./docs.out
./run.sh cli passgen --length 24
./run.sh cli passgen --words 6 --separator "-"
./run.sh cli shred ./old-secrets.txt --passes 3
./run.sh cli shamir split "master secret" --shares 5 --threshold 3
./run.sh cli shamir combine <share1> <share2> <share3>
```

---

## Command Notes

### `keygen`

Required flags:

- `--algorithm <rsa2048|rsa4096|ed25519|x25519|pgp>`
- `--label <LABEL>`

### `encrypt`

Required flags:

- `--input <INPUT>`
- `--output <OUTPUT>`

Important options:

- `--password` for password-based encryption
- `--recipient <RECIPIENT>` for public-key encryption
- `--algorithm <aes256gcm|chacha20>`
- `--passphrase-file <FILE>` to read a passphrase from disk
- `--compress` to enable pre-encryption compression

### `decrypt`

Required flags:

- `--input <INPUT>`
- `--output <OUTPUT>`

Optional:

- `--key <KEY>` to select a decryption key
- `--passphrase <PASSPHRASE>` or `--passphrase-file <FILE>`

### `backup`

Subcommands:

```bash
./run.sh cli backup create --output backup.hbzf
./run.sh cli backup restore --input backup.hbzf
./run.sh cli backup verify --input backup.hbzf
```

### `config`

Supported subcommands:

```bash
./run.sh cli config get <key>
./run.sh cli config set <key> <value>
./run.sh cli config list
./run.sh cli config reset
./run.sh cli config path
```

Browser-facing config aliases such as `cipher`, `kdf`, and `clipboard_auto_clear` are supported by the current runtime.

---

## Environment

| Variable | Purpose |
|----------|---------|
| `HB_ZAYFER_HOME` | Override the default workspace at `~/.hb_zayfer/` |

For headless GUI smoke tests, CI also uses `HB_ZAYFER_SKIP_ONBOARDING=1`, but that is not required for normal CLI use.

---

## Exit Codes

| Code | Meaning |
|------|---------|
| `0` | Success |
| `1` | Operational failure or invalid result |
| `2` | Invalid usage or missing required arguments |

