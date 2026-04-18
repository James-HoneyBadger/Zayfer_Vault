# Zayfer Vault User Guide

Complete guide for users of the Zayfer Vault encryption suite. Covers all four
interfaces (Desktop GUI, CLI, Python API, Web UI) and common workflows.

**Version 1.0.1** — Zayfer Vault Encryption Suite

---

## Table of Contents

1. [Introduction](#introduction)
2. [Getting Started](#getting-started)
3. [Key Management](#key-management)
4. [Encryption & Decryption](#encryption--decryption)
5. [Digital Signatures](#digital-signatures)
6. [Contacts Management](#contacts-management)
7. [Password Generation](#password-generation)
8. [Shamir's Secret Sharing](#shamirs-secret-sharing)
9. [Secure Shredding](#secure-shredding)
10. [QR Key Exchange](#qr-key-exchange)
11. [Backup & Recovery](#backup--recovery)
12. [Audit & Security](#audit--security)
13. [Configuration](#configuration)
14. [Desktop GUI Reference](#desktop-gui-reference)
15. [Advanced Topics](#advanced-topics)
16. [Troubleshooting](#troubleshooting)

---

## Introduction

### What is Zayfer Vault?

Zayfer Vault is a comprehensive encryption toolkit that provides:

- **File encryption** with AES-256-GCM or ChaCha20-Poly1305
- **Public-key cryptography** using RSA, Ed25519, and X25519
- **OpenPGP support** for GPG-compatible key exchange
- **Digital signatures** for authentication and integrity
- **Secure key storage** with password-protected private keys
- **Contact management** for organising encryption recipients
- **Password & passphrase generation** with entropy scoring
- **Shamir's Secret Sharing** for splitting secrets among custodians
- **Steganography** for hiding data in images
- **Secure file shredding** (multi-pass overwrite + unlink)
- **QR key exchange** via `hbzf-key://` URIs
- **Encrypted backups** with passphrase-protected keystore snapshots
- **Audit logging** with tamper-evident hash-chain integrity
- **Configuration system** (TOML) with presets

All cryptographic operations run in native Rust via `hb_zayfer_core` (20 modules),
ensuring memory safety and high performance.

### Choosing an Interface

| Interface | Best For | Launch Command |
|-----------|----------|----------------|
| **Desktop GUI** | Visual users, 14 sidebar views | `./run.sh` or `./run.sh gui` |
| **CLI** | Terminal users, scripting, automation | `./run.sh cli <command>` |
| **Web UI** | Browser access, REST API integration | `./run.sh web` |
| **Python API** | Programmatic use, embedding | `import hb_zayfer` |

All interfaces share the same keystore at `~/.hb_zayfer/`.

### Documentation Map

If you are new to Zayfer Vault or to encryption in general, use this order:

1. [`QUICKSTART.md`](QUICKSTART.md) — fastest way to launch and verify the app
2. [`TUTORIAL_ENCRYPTION_PASSWORDS.md`](TUTORIAL_ENCRYPTION_PASSWORDS.md) — safe password and encryption walkthrough
3. [`USER_GUIDE.md`](USER_GUIDE.md) — full day-to-day usage reference
4. [`TECHNICAL_REFERENCE.md`](../reference/TECHNICAL_REFERENCE.md) — exact commands, parameters, and endpoints
5. [`MAINTENANCE.md`](MAINTENANCE.md) — backup, upgrade, and recovery procedures

### Safety-First Setup Checklist

Before storing important data, make sure you have done the following:

- generated or imported the keys you actually need,
- verified at least one backup with `hb-zayfer backup verify`,
- decided whether your workflow uses **password-based** or **recipient-based** encryption,
- stored passphrases in a secure password manager, and
- verified key fingerprints through a second channel before trusting other people's public keys.

---

## Getting Started

### First Launch

Zayfer Vault creates:

```
~/.hb_zayfer/
├── config.toml           # Configuration (TOML)
├── keys/
│   ├── private/          # Encrypted private keys (AES-256-GCM + Argon2id)
│   └── public/           # Public key material
├── keyring.json          # Key metadata index
├── contacts.json         # Contact ↔ key associations
└── audit.json            # Tamper-evident audit log
```

Override with `HB_ZAYFER_HOME` environment variable.

### Basic Workflow

1. **Generate or import keys** for encryption and signing
2. **Add contacts** and associate their public keys
3. **Encrypt files** using a password or a recipient's public key
4. **Decrypt** with your private key and passphrase
5. **Sign** documents to prove authenticity
6. **Verify** signatures from others
7. **Back up** your keystore regularly

---

## Key Management

### Key Types

| Algorithm | Type | Use Case | Key Size |
|-----------|------|----------|----------|
| **RSA-2048** | Asymmetric | Encrypt + sign | 2048-bit |
| **RSA-4096** | Asymmetric | High-security encrypt + sign | 4096-bit |
| **Ed25519** | Asymmetric | Digital signatures (fast) | 256-bit |
| **X25519** | Asymmetric | Key exchange / encryption (ECDH) | 256-bit |
| **PGP** | Asymmetric | GPG-compatible email encryption | Variable |

**Recommendations:**

- **Ed25519** for signatures — fast, small, 128-bit security
- **X25519** for encryption — modern ECDH
- **RSA-4096** for legacy compatibility
- **PGP** for GPG/OpenPGP interop

### Generating Keys

#### GUI

1. Click **🔑 Key Gen** (Alt+3)
2. Select algorithm, enter label, enter passphrase
3. The password strength meter shows real-time entropy
4. Click **Generate** — toast notification shows fingerprint

#### CLI

```bash
hb-zayfer keygen ed25519 --label "My Signing Key"
hb-zayfer keygen x25519 --label "My Encryption Key"
hb-zayfer keygen rsa4096 --label "Server Key"
hb-zayfer keygen pgp --label "My PGP Key" --user-id "Alice <alice@example.com>"
```

### Viewing Keys

#### GUI

Click **📦 Keyring** (Alt+4) — sortable table, search box, right-click context menu.

#### CLI

```bash
hb-zayfer keys list                              # Table of all keys
hb-zayfer keys list --json                       # JSON output
hb-zayfer keys export <fp> --output pubkey.pem   # Export public key
hb-zayfer keys import keyfile.pem --label "Name" --algorithm ed25519
hb-zayfer keys delete <fp>                       # Delete (with confirmation)
```

### Key Fingerprints

Every key has a SHA-256 fingerprint (64 hex characters). Use fingerprint
prefixes (≥ 4 chars) in CLI commands. Verify fingerprints through a
separate channel before trusting.

---

## Encryption & Decryption

### Wrapping Modes

| Mode | How It Works |
|------|-------------|
| **Password** | Passphrase → Argon2id → 32-byte key → AEAD |
| **RSA** | Random DEK → RSA-OAEP wrap → AEAD |
| **X25519** | Ephemeral ECDH → HKDF → 32-byte key → AEAD |

### Encrypting Files

#### GUI

1. Click **🔐 Encrypt** (Alt+1)
2. Choose **File** or **Text** tab
3. Browse or drag-and-drop a file
4. Choose algorithm (AES-256-GCM or ChaCha20-Poly1305)
5. Select wrapping: **Password** or **Recipient** (autocomplete contact names)
6. Click **Encrypt**

#### CLI

```bash
hb-zayfer encrypt secret.txt -p                   # Password + AES (default)
hb-zayfer encrypt secret.txt -p -a chacha          # Password + ChaCha
hb-zayfer encrypt secret.txt -o out.hbzf -p        # Custom output
hb-zayfer encrypt secret.txt --recipient alice      # Public-key (contact name)
```

### Decrypting Files

#### GUI

1. Click **🔓 Decrypt** (Alt+2)
2. Browse or drag-and-drop the `.hbzf` file
3. Auto-detects wrapping mode; enter passphrase or select private key
4. Click **Decrypt**

#### CLI

```bash
hb-zayfer decrypt secret.txt.hbzf                  # Interactive passphrase
hb-zayfer decrypt secret.txt.hbzf -o recovered.txt # Specify output
hb-zayfer decrypt message.hbzf -k <fp>             # Public-key mode
```

### Directory Encryption

Encrypt or decrypt all files in a directory:

```bash
hb-zayfer encrypt-dir -i ./documents -o ./encrypted -p -a aes
hb-zayfer decrypt-dir -i ./encrypted -o ./recovered
```

### Algorithm Selection

| Algorithm | Speed | Best For |
|-----------|-------|----------|
| **AES-256-GCM** | Very fast (AES-NI) | Desktop / server (x86) |
| **ChaCha20-Poly1305** | Consistent | ARM, mobile, embedded |

---

## Digital Signatures

### Signing

#### GUI

Click **✍️ Sign** (Alt+6) — select file, choose signing key, click **Sign**.

#### CLI

```bash
hb-zayfer sign document.pdf --key <fp>
hb-zayfer sign document.pdf --key <fp> -o document.pdf.sig
```

### Verifying

#### GUI

Click **✔️ Verify** (Alt+7) — select file + signature, choose signer's key.

#### CLI

```bash
hb-zayfer verify document.pdf document.pdf.sig --key <signer-fp>
# Output: "Signature is VALID" or "Signature is INVALID"
```

**Tip:** Use **Ed25519** for signatures — faster and more compact than RSA.

---

## Contacts Management

### Adding Contacts

#### GUI

Click **👥 Contacts** (Alt+5) → **Add Contact** → enter name, email, notes →
right-click → **Link Key**.

#### CLI

```bash
hb-zayfer contacts add "Alice" --email alice@example.com
hb-zayfer contacts link "Alice" <fingerprint>
hb-zayfer contacts list
hb-zayfer contacts remove "Alice"
```

Once contacts have linked keys, encrypt by name:

```bash
hb-zayfer encrypt secret.txt --recipient alice
```

---

## Password Generation

### GUI

Click **🔐 PassGen** (Alt+8):

- **Password** tab: set length, toggle character classes, exclude ambiguous chars
- **Passphrase** tab: set word count, choose separator
- Real-time entropy bar shows strength
- Click **Generate**, then **Copy** to clipboard

### CLI

```bash
hb-zayfer passgen                             # Default 20-char password
hb-zayfer passgen --length 32                 # 32-char password
hb-zayfer passgen --exclude "0O1lI"           # Skip ambiguous chars
hb-zayfer passgen --passphrase                # Diceware passphrase
hb-zayfer passgen --passphrase --words 8      # 8-word passphrase
hb-zayfer passgen --json                      # JSON with entropy
```

### Python API

```python
import hb_zayfer as hbz
pw = hbz.generate_password(length=24, exclude="0O1lI")
phrase = hbz.generate_passphrase(words=6, separator="-")
print(f"Password entropy: {hbz.password_entropy(24):.1f} bits")
```

---

## Shamir's Secret Sharing

Split a secret into N shares where any K can reconstruct it.

### CLI

```bash
# Split into 5 shares, need 3 to reconstruct
hb-zayfer shamir split --secret "master-passphrase" -n 5 -k 3

# Reconstruct from shares
hb-zayfer shamir combine --shares "share1hex,share2hex,share3hex"
```

### Python API

```python
shares = hbz.shamir_split(b"my-secret", 5, 3)
recovered = hbz.shamir_combine(shares[:3])
```

### Use Cases

- Split a master passphrase among 5 executives (3-of-5 quorum)
- Distribute key escrow shares to multiple locations
- Dead-man's switch: shares held by trusted parties

---

## Secure Shredding

Overwrite files with random data before deletion (multi-pass).

### CLI

```bash
hb-zayfer shred sensitive.txt                   # 3-pass default
hb-zayfer shred sensitive.txt --passes 7        # 7-pass overwrite
hb-zayfer shred -r ./temp-data/                 # Recursive directory shred
```

### GUI

The Settings view includes a **Confirm before shred** toggle. Shred operations
are logged in the audit trail.

### Limitations

- Journaling filesystems may retain journal copies
- SSD wear-levelling may keep old data
- For maximum security, combine with full-disk encryption (LUKS/dm-crypt)

---

## QR Key Exchange

Share public keys by scanning QR codes (phone-to-phone, laptop-to-phone).

### GUI

Click **📱 QR Exchange** — enter algorithm + fingerprint → generates QR code.
Scan a QR code to import a key URI.

### CLI / Python

```python
uri = hbz.qr_encode_key_uri("ed25519", "a1b2c3d4...", "Alice")
# hbzf-key://ed25519/a1b2c3d4...?label=Alice

algo, fp, label = hbz.qr_decode_key_uri(uri)
```

---

## Backup & Recovery

### Creating Backups

#### GUI

Click **💾 Backup** → **Create Backup** → choose output path → enter passphrase.

#### CLI

```bash
hb-zayfer backup create -o ~/backup.hbzf
hb-zayfer backup create -o ~/backup.hbzf --label "Weekly"
hb-zayfer backup verify -i ~/backup.hbzf       # Verify integrity
hb-zayfer backup restore -i ~/backup.hbzf       # Restore (overwrites keystore)
```

### Best Practices

- Back up after generating new keys or adding important contacts
- Store in multiple locations (encrypted cloud + offline USB)
- Use a **different** passphrase from your key passphrases
- Test restoring periodically
- Keep 3+ backup generations

### Disaster Recovery

If you lose your keystore:
1. Restore from backup: `hb-zayfer backup restore -i backup.hbzf`
2. Verify: `hb-zayfer keys list`
3. If keys are missing, inform contacts of your new keys

Forgotten passphrases cannot be recovered — Argon2id + AES-256-GCM is irreversible.

---

## Audit & Security

### Audit Log

Zayfer Vault logs all cryptographic operations with a tamper-evident hash chain.

#### GUI

Click **📋 Audit Log** (Alt+0) — browse entries, verify integrity, export.

#### CLI

```bash
hb-zayfer audit                          # Recent 20 entries
hb-zayfer audit --limit 50              # More entries
hb-zayfer audit verify                   # Verify hash-chain integrity
hb-zayfer audit export -o audit.json     # Export
```

### What Is Logged

Key generation, file encryption/decryption, signing, signature verification,
contact add/delete, key deletion — each with timestamp, entry hash, and
previous hash for chain integrity.

---

## Configuration

### GUI

Click **⚙️ Settings** — theme (dark/light/auto), font size, default algorithm,
KDF preset, confirm-shred toggle.

### CLI

```bash
hb-zayfer config list                    # Show all settings
hb-zayfer config get default_algorithm   # Get a value
hb-zayfer config set default_algorithm chacha  # Set a value
hb-zayfer config reset                   # Reset to defaults
hb-zayfer config path                    # Show config file location
```

### Configuration Keys

| Key | Default | Values |
|-----|---------|--------|
| `default_algorithm` | `aes` | `aes`, `chacha` |
| `default_kdf` | `standard` | `low`, `standard`, `high`, `paranoid` |
| `gui.theme` | `dark` | `dark`, `light`, `auto` |
| `gui.font_size` | `13.0` | Any float |
| `gui.confirm_shred` | `true` | `true`, `false` |
| `cli.color` | `true` | `true`, `false` |
| `cli.json_output` | `false` | `true`, `false` |

---

## Desktop GUI Reference

### 14 Sidebar Views

| # | View | Shortcut | Purpose |
|---|------|----------|---------|
| 1 | 🏠 Home | — | Overview dashboard, counts, and quick actions |
| 2 | 🔐 Encrypt | Alt+1 | Encrypt files or text |
| 3 | 🔓 Decrypt | Alt+2 | Decrypt `.hbzf` files or text |
| 4 | 🔑 Key Gen | Alt+3 | Generate key pairs |
| 5 | 📦 Keyring | Alt+4 | Browse, search, export, delete keys |
| 6 | 👥 Contacts | Alt+5 | Manage contacts and link keys |
| 7 | ✍️ Sign | Alt+6 | Sign files with Ed25519/RSA/PGP |
| 8 | ✔️ Verify | Alt+7 | Verify signatures |
| 9 | 🔐 PassGen | Alt+8 | Password & passphrase generator |
| 10 | 💬 Messaging | Alt+9 | End-to-end encrypted messaging |
| 11 | 📱 QR Exchange | — | Share keys via QR codes |
| 12 | ⚙️ Settings | — | Preferences and theme |
| 13 | 📋 Audit Log | Alt+0 | Browse and verify audit trail |
| 14 | 💾 Backup | — | Create, verify, restore backups |

### Keyboard Shortcuts

| Shortcut | Action |
|----------|--------|
| Ctrl+Q | Quit |
| Alt+1–9 | Switch to views 1–9 |
| Alt+0 | Switch to Audit Log |
| Ctrl+F | Focus search (Keyring / Contacts) |
| Ctrl+R | Refresh current view |

### Features

- **Drag & Drop** — Drop files onto Encrypt/Decrypt views
- **Background Workers** — Crypto ops run in QThread (UI stays responsive)
- **Password Strength Meter** — Real-time entropy bar
- **Dark / Light / Auto Themes** — Switch in Settings
- **Toast Notifications** — Green (success), red (error), yellow (warning), blue (info)

---

## Advanced Topics

### Custom Keystore Location

```bash
export HB_ZAYFER_HOME="/mnt/secure/.hb_zayfer"
hb-zayfer keys list   # Uses custom location
```

### Environment Variables Reference

| Variable | Default | Description |
|----------|---------|-------------|
| `HB_ZAYFER_HOME` | `~/.hb_zayfer` | Data directory for keys, contacts, audit logs, and config |
| `HB_ZAYFER_API_TOKEN` | *(unset)* | Bearer token for web API authentication. When set, all requests must include `Authorization: Bearer <token>` |
| `HB_ZAYFER_RATE_LIMIT` | `60` | Maximum API requests per client IP per window |
| `HB_ZAYFER_RATE_WINDOW` | `60` | Rate-limit window duration in seconds |
| `HB_ZAYFER_PORT` | `8000` | Default port for the web server (overridden by `--port`) |

### Batch Encryption

```bash
# Encrypt all PDFs in a directory
hb-zayfer encrypt-dir -i ./documents -o ./encrypted -p -a aes

# Or loop individually
for f in *.pdf; do hb-zayfer encrypt "$f" -p; done
```

### JSON Output

All CLI commands support `--json` for structured output:

```bash
hb-zayfer keys list --json
hb-zayfer passgen --json
hb-zayfer audit --json
```

### Shell Completions

```bash
hb-zayfer completions bash > ~/.local/share/bash-completion/completions/hb-zayfer
hb-zayfer completions zsh  > ~/.zfunc/_hb-zayfer
hb-zayfer completions fish > ~/.config/fish/completions/hb-zayfer.fish
```

### HBZF File Inspection

View metadata of an encrypted file without decrypting:

```bash
hb-zayfer inspect encrypted.hbzf
# Shows: algorithm, wrapping mode, KDF params, chunk count
```

### Python API Integration

```python
import hb_zayfer as hbz

# Encrypt / decrypt
hbz.encrypt_file("secret.pdf", "secret.pdf.hbzf",
                  algorithm="aes", wrapping="password",
                  passphrase=b"my-password")
hbz.decrypt_file("secret.pdf.hbzf", "recovered.pdf",
                  passphrase=b"my-password")

# Key management
ks = hbz.KeyStore()
for k in ks.list_keys():
    print(f"{k.label}: {k.algorithm} ({k.fingerprint[:16]}..)")
```

See [PYTHON_API.md](../reference/PYTHON_API.md) for the full reference.

---

## Troubleshooting

### Common Issues

#### "Permission denied"

```bash
chmod 700 ~/.hb_zayfer/
chmod 700 ~/.hb_zayfer/keys/private/
chmod 600 ~/.hb_zayfer/keys/private/*.key
```

#### "Wrong passphrase"

No recovery possible. Generate new keys or restore from backup.

#### "Key not found"

```bash
hb-zayfer keys list   # Find correct fingerprint
hb-zayfer decrypt message.hbzf -k a1b2   # Use prefix (≥ 4 chars)
```

#### GUI does not start

```bash
source .venv/bin/activate
pip install PySide6
echo $DISPLAY   # Must be set on Linux
```

#### Slow RSA-4096 keygen

Normal on slower CPUs (30–60 s). Use Ed25519/X25519 for faster generation.

### Diagnostic Commands

```bash
hb-zayfer --version
python -c "import hb_zayfer; print(hb_zayfer.version())"
hb-zayfer keys list
hb-zayfer audit verify
hb-zayfer config list
```

---

**See also:**
[Quick Start](QUICKSTART.md) ·
[CLI Reference](../reference/CLI.md) ·
[Python API](../reference/PYTHON_API.md) ·
[Security](../reference/SECURITY.md) ·
[Secure Communications](SECURE_COMMUNICATIONS.md)
