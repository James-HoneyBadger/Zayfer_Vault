# CLI Reference

**Zayfer Vault v1.0.1**

Zayfer Vault provides two command-line interfaces: a **Python CLI** (Click-based,
installed via pip) and a **Rust CLI** (compiled binary via Cargo).

Both CLIs expose the same core functionality. The Python CLI has richer output
formatting (Rich tables, spinners); the Rust CLI uses clap and differs only in
flag style.

---

## Python CLI (`hb-zayfer`)

Installed automatically with `pip install -e ".[cli]"`. Requires `click` and
`rich`.

### Global Options

```
hb-zayfer --version    Show version and exit
hb-zayfer --help       Show help for any command
hb-zayfer --json       Enable JSON output mode (where supported)
```

---

### `keygen` — Generate a Key Pair

```bash
hb-zayfer keygen ALGORITHM [OPTIONS]
```

| Argument | Required | Values |
|----------|----------|--------|
| `ALGORITHM` | Yes | `rsa2048`, `rsa4096`, `ed25519`, `x25519`, `pgp` |

| Option | Description |
|--------|-------------|
| `--label, -l` | Human-readable label (**required**) |
| `--user-id, -u` | User ID for PGP keys (e.g. `"Name <email>"`) |
| `--export-dir, -o` | Directory to export the public key file |
| `--passphrase-file` | Read passphrase from a file (useful for scripting) |

You will be prompted for a passphrase to protect the private key.

**Examples:**

```bash
# Generate an Ed25519 signing key
hb-zayfer keygen ed25519 -l "My Signing Key"

# Generate RSA-4096 and export the public key
hb-zayfer keygen rsa4096 -l server-key -o ./keys/

# Generate a PGP certificate
hb-zayfer keygen pgp -l "Work Key" -u "Jane <jane@corp.com>"

# Generate an X25519 key for encryption
hb-zayfer keygen x25519 -l "Encryption Key"

# Non-interactive with passphrase from file
hb-zayfer keygen ed25519 -l "CI Key" --passphrase-file /secrets/pw.txt
```

---

### `encrypt` — Encrypt a File

```bash
hb-zayfer encrypt INPUT_FILE [OPTIONS]
```

| Option | Description |
|--------|-------------|
| `--output, -o` | Output file (default: `<input>.hbzf`) |
| `--algorithm, -a` | `aes` (default) or `chacha` |
| `--password, -p` | Use password-based encryption |
| `--recipient, -r` | Contact name or fingerprint prefix (may specify multiple) |
| `--passphrase-file` | Read passphrase from file |

If neither `--password` nor `--recipient` is given, defaults to password mode.

**Examples:**

```bash
# Password-based encryption (prompted)
hb-zayfer encrypt secret.pdf -p

# Encrypt to a contact using AES-256-GCM
hb-zayfer encrypt report.xlsx -r Alice

# Encrypt with ChaCha20-Poly1305 and custom output
hb-zayfer encrypt data.bin -p -a chacha -o data.enc

# Multi-recipient encryption
hb-zayfer encrypt secret.pdf -r Alice -r Bob
```

---

### `decrypt` — Decrypt an HBZF File

```bash
hb-zayfer decrypt INPUT_FILE [OPTIONS]
```

| Option | Description |
|--------|-------------|
| `--output, -o` | Output file (default: strip `.hbzf` suffix) |
| `--key, -k` | Fingerprint prefix of decryption key (for public-key mode) |
| `--passphrase-file` | Read passphrase from file |

The CLI auto-detects the wrapping mode from the HBZF header and prompts
accordingly.

**Examples:**

```bash
# Decrypt password-encrypted file
hb-zayfer decrypt secret.pdf.hbzf

# Decrypt with a specific key
hb-zayfer decrypt message.hbzf -k a1b2c3d4

# Specify output path
hb-zayfer decrypt archive.hbzf -o /tmp/recovered.tar
```

---

### `sign` — Sign a File

```bash
hb-zayfer sign INPUT_FILE [OPTIONS]
```

| Option | Description |
|--------|-------------|
| `--key, -k` | Fingerprint prefix of the signing key |
| `--output, -o` | Signature output file (default: `<input>.sig`) |
| `--algorithm, -a` | `ed25519` (default), `rsa`, or `pgp` |

**Examples:**

```bash
hb-zayfer sign document.pdf -k a1b2c3
hb-zayfer sign firmware.bin -k abc123 -a rsa -o firmware.sig
hb-zayfer sign message.txt -k def456 -a pgp
```

---

### `verify` — Verify a Signature

```bash
hb-zayfer verify INPUT_FILE SIGNATURE_FILE [OPTIONS]
```

| Option | Description |
|--------|-------------|
| `--key, -k` | Fingerprint prefix or contact name (**required**) |
| `--algorithm, -a` | `ed25519` (default), `rsa`, or `pgp` |

Exit code `0` if valid, `1` if invalid.

---

### `keys` — Key Management

#### `keys list`

```bash
hb-zayfer keys list [--json]
```

Lists all keys in the keyring in a table: label, algorithm, fingerprint,
private/public status, and creation date. With `--json`, outputs JSON array.

#### `keys export`

```bash
hb-zayfer keys export FINGERPRINT_PREFIX [OPTIONS]
```

| Option | Description |
|--------|-------------|
| `--output, -o` | Output file (stdout if omitted) |

#### `keys import`

```bash
hb-zayfer keys import KEY_FILE [OPTIONS]
```

| Option | Description |
|--------|-------------|
| `--label, -l` | Label for the imported key (**required**) |
| `--algorithm, -a` | Algorithm type (**required**): `rsa2048`, `rsa4096`, `ed25519`, `x25519`, `pgp` |
| `--private` | Import as a private key (will be passphrase-encrypted) |

Supports PEM, DER, ASCII-armored PGP, and OpenSSH formats.

#### `keys delete`

```bash
hb-zayfer keys delete FINGERPRINT_PREFIX [OPTIONS]
```

| Option | Description |
|--------|-------------|
| `--yes, -y` | Skip confirmation prompt |

---

### `contacts` — Contact Management

#### `contacts list`

```bash
hb-zayfer contacts list
```

#### `contacts add`

```bash
hb-zayfer contacts add NAME [OPTIONS]
```

| Option | Description |
|--------|-------------|
| `--email, -e` | Email address (optional) |
| `--notes, -n` | Free-form notes (optional) |

#### `contacts remove`

```bash
hb-zayfer contacts remove NAME [--yes]
```

#### `contacts link`

```bash
hb-zayfer contacts link CONTACT_NAME FINGERPRINT_PREFIX
```

Associates a key with a contact for recipient-based encryption.

---

### `backup` — Keystore Backup & Restore

#### `backup create`

```bash
hb-zayfer backup create -o OUTPUT_FILE [--label LABEL]
```

#### `backup restore`

```bash
hb-zayfer backup restore -i BACKUP_FILE [--yes]
```

#### `backup verify`

```bash
hb-zayfer backup verify -i BACKUP_FILE
```

---

### `audit` — Audit Log

#### `audit show`

```bash
hb-zayfer audit show [-n LIMIT]
```

| Option | Description |
|--------|-------------|
| `--limit, -n` | Number of entries to show (default: 20) |

#### `audit verify`

```bash
hb-zayfer audit verify
```

Verifies the audit log's HMAC integrity chain. Exit code `0` if intact.

#### `audit export`

```bash
hb-zayfer audit export -o OUTPUT_FILE
```

---

### `config` — Configuration Management

#### `config list`

```bash
hb-zayfer config list
```

Shows all configuration key-value pairs.

#### `config get`

```bash
hb-zayfer config get KEY
```

Print the value of a single configuration key.

#### `config set`

```bash
hb-zayfer config set KEY VALUE
```

Set a configuration value. Common keys:

| Key | Values | Description |
|-----|--------|-------------|
| `default_algorithm` | `aes`, `chacha` | Default symmetric algorithm |
| `kdf_algorithm` | `argon2id`, `scrypt` | Default KDF |
| `chunk_size` | integer bytes | HBZF chunk size (default: 65536) |

#### `config reset`

```bash
hb-zayfer config reset
```

Reset configuration to defaults.

#### `config path`

```bash
hb-zayfer config path
```

Print the configuration file path.

---

### `inspect` — Inspect HBZF File

```bash
hb-zayfer inspect FILE
```

Displays HBZF header metadata without decrypting:

- Symmetric algorithm (AES-256-GCM or ChaCha20-Poly1305)
- KDF algorithm (Argon2id, scrypt, or none)
- Key wrapping mode (password, RSA-OAEP, or X25519)
- Plaintext file size

---

### `encrypt-dir` — Batch Encrypt Directory

```bash
hb-zayfer encrypt-dir DIRECTORY [OPTIONS]
```

| Option | Description |
|--------|-------------|
| `--password, -p` | Use password-based encryption |
| `--recipient, -r` | Contact name or fingerprint prefix |
| `--algorithm, -a` | `aes` (default) or `chacha` |

Recursively encrypts all files in the directory, creating `.hbzf` files.

---

### `decrypt-dir` — Batch Decrypt Directory

```bash
hb-zayfer decrypt-dir DIRECTORY [OPTIONS]
```

| Option | Description |
|--------|-------------|
| `--key, -k` | Fingerprint prefix (for public-key mode) |

Recursively decrypts all `.hbzf` files found in the directory tree.

---

### `completions` — Shell Completions

```bash
hb-zayfer completions SHELL
```

| Shell | Example |
|-------|---------|
| `bash` | `hb-zayfer completions bash > ~/.local/share/bash-completion/completions/hb-zayfer` |
| `zsh` | `hb-zayfer completions zsh > ~/.zfunc/_hb-zayfer` |
| `fish` | `hb-zayfer completions fish > ~/.config/fish/completions/hb-zayfer.fish` |
| `elvish` | `hb-zayfer completions elvish` |
| `powershell` | `hb-zayfer completions powershell` |

---

### `shred` — Secure File Shredding

```bash
hb-zayfer shred TARGET [OPTIONS]
```

| Option | Description |
|--------|-------------|
| `--passes, -p` | Number of overwrite passes (default: 3) |
| `--recursive, -r` | Recursively shred directory contents |

Overwrites file(s) with cryptographically random data multiple times before
deleting. Supports `--json` output mode.

**Examples:**

```bash
# Shred a single file with 3 passes
hb-zayfer shred secret.txt -p 3

# Recursively shred a directory
hb-zayfer shred ./temp-secrets -r

# JSON output
hb-zayfer shred old.txt --json
```

---

### `passgen` — Password & Passphrase Generator

```bash
hb-zayfer passgen [OPTIONS]
```

| Option | Description |
|--------|-------------|
| `--length` | Password length in characters (default: 20) |
| `--words` | Generate a passphrase with N words (overrides --length) |
| `--separator` | Word separator for passphrases (default: space) |
| `--exclude` | Characters to exclude from passwords |
| `--json` | Output in JSON format |

**Examples:**

```bash
# 24-character random password
hb-zayfer passgen --length 24

# 6-word passphrase with dashes
hb-zayfer passgen --words 6 --separator "-"

# Exclude ambiguous characters
hb-zayfer passgen --length 20 --exclude "0O1lI"

# JSON output (for scripting)
hb-zayfer passgen --json
```

---

### `shamir` — Shamir's Secret Sharing

#### `shamir split`

```bash
hb-zayfer shamir split [OPTIONS]
```

| Option | Description |
|--------|-------------|
| `--shares, -n` | Total number of shares to create (**required**) |
| `--threshold, -t` | Minimum shares needed to reconstruct (**required**) |
| `--secret, -s` | The secret to split (prompted if not provided) |
| `--json` | Output shares in JSON format |

#### `shamir combine`

```bash
hb-zayfer shamir combine [OPTIONS]
```

| Option | Description |
|--------|-------------|
| `--shares, -s` | Comma-separated hex-encoded shares (**required**) |

**Examples:**

```bash
# Split a secret into 5 shares, needing 3 to reconstruct
hb-zayfer shamir split -n 5 -t 3 -s "master passphrase"

# Combine 3 shares to recover the secret
hb-zayfer shamir combine -s abc123,def456,789abc

# JSON output for scripting
hb-zayfer shamir split -n 5 -t 3 -s "secret" --json
```

---

### `encrypt-text` — Encrypt Text from Stdin

```bash
echo "secret data" | hb-zayfer encrypt-text [-a aes|chacha]
```

### `decrypt-text` — Decrypt Text from Stdin

```bash
echo "BASE64..." | hb-zayfer decrypt-text
```

---

## Rust CLI (`hb_zayfer_cli`)

The Rust CLI provides the same commands with long-form flags:

```bash
# From source
cargo run --bin hb_zayfer_cli -- <COMMAND> [OPTIONS]

# After cargo install
hb-zayfer <COMMAND> [OPTIONS]
```

### All Commands

| Command | Description |
|---------|-------------|
| `keygen` | Generate key pair |
| `encrypt` | Encrypt a file |
| `decrypt` | Decrypt an HBZF file |
| `sign` | Sign a file |
| `verify` | Verify a signature |
| `keys` | Key management (list, export, import, delete) |
| `contacts` | Contact management (list, add, remove) |
| `backup` | Keystore backup (create, restore, verify) |
| `audit` | Audit log (show, verify, export) |
| `config` | Configuration (get, set, list, reset, path) |
| `inspect` | Inspect HBZF file headers |
| `encrypt-dir` | Batch encrypt directory |
| `decrypt-dir` | Batch decrypt directory |
| `completions` | Generate shell completions |
| `shred` | Secure file shredding |
| `passgen` | Password/passphrase generation |
| `shamir` | Shamir's Secret Sharing (split, combine) |

### Global Flag

```
--json    Output in JSON format (supported: keys list, passgen, shamir, shred)
```

### Pipe-Friendly I/O

Both `--input` and `--output` accept `-` for stdin/stdout:

```bash
cat secret.txt | cargo run --bin hb_zayfer_cli -- \
  encrypt --input - --output - --password > encrypted.hbzf
```

---

## Environment Variables

| Variable | Description |
|----------|-------------|
| `HB_ZAYFER_HOME` | Override keystore directory (default: `~/.hb_zayfer/`) |
| `HB_ZAYFER_API_TOKEN` | Bearer token for web API authentication |

---

## Exit Codes

| Code | Meaning |
|------|---------|
| `0` | Success |
| `1` | Failure (invalid signature, bad passphrase, missing key, etc.) |
| `2` | Usage error (missing argument, invalid option) |
