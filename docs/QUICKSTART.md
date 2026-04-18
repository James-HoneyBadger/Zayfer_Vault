# Quick Start Guide

Get up and running with Zayfer Vault in 10 minutes.

**Version 1.0.1** — Zayfer Vault Encryption Suite

---

## 5-Minute Installation

### Prerequisites

- Linux, macOS, or Windows
- Python 3.10+
- Rust 1.75+ (stable)
- 500 MB disk space

### One-Command Launch (Recommended)

```bash
# 1. Install Rust (skip if already installed)
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
source "$HOME/.cargo/env"

# 2. Clone and launch
git clone https://github.com/James-HoneyBadger/Zayfer_Vault.git
cd Zayfer_Vault
./run.sh      # Handles venv, deps, native build, and launches the GUI
```

The `run.sh` script auto-detects what's missing and installs/builds as needed.

### Manual Install

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
source "$HOME/.cargo/env"

git clone https://github.com/James-HoneyBadger/Zayfer_Vault.git
cd Zayfer_Vault

python3 -m venv .venv
source .venv/bin/activate  # Linux/macOS
# OR: .venv\Scripts\activate on Windows

pip install maturin
pip install -e ".[all]"
maturin develop --release -m crates/python/Cargo.toml

python -c "import hb_zayfer; print(f'Zayfer Vault v{hb_zayfer.version()}')" 
```

**Having trouble?** See [INSTALL.md](../INSTALL.md) for platform-specific troubleshooting.

---

## Your First Encrypted File (CLI)

```bash
# Activate environment first
source .venv/bin/activate

# 1. Create a test file
echo "My secret message" > secret.txt

# 2. Encrypt with a password
hb-zayfer encrypt secret.txt -p
# Enter and confirm a passphrase when prompted
# Output: secret.txt.hbzf

# 3. Decrypt
hb-zayfer decrypt secret.txt.hbzf
# Enter the same passphrase
# Output: secret.txt

# 4. Verify
cat secret.txt
# Output: My secret message
```

**Success!** You've encrypted and decrypted your first file.

---

## Your First Key Pair

```bash
# Generate an Ed25519 signing key
hb-zayfer keygen ed25519 --label "My First Key"
# Enter and confirm a strong passphrase

# List your keys
hb-zayfer keys list
# Shows: label, algorithm, fingerprint, created date

# Export your public key to share with others
hb-zayfer keys export <fingerprint-prefix> --output my_public_key.pem
```

Your keystore is stored under `~/.hb_zayfer/` with encrypted private keys.

---

## Launch the GUI

```bash
source .venv/bin/activate
hb-zayfer-gui
```

### GUI Quick Tour

The GUI has **14 sidebar views** with keyboard shortcuts:

| View | Shortcut | What It Does |
|------|----------|--------------|
| 🏠 **Home** | — | Overview dashboard with quick actions and onboarding guidance |
| 🔐 **Encrypt** | `Alt+1` | Encrypt files or text — drag-and-drop supported |
| 🔓 **Decrypt** | `Alt+2` | Decrypt `.hbzf` files or base64 text |
| 🔑 **Key Gen** | `Alt+3` | Generate key pairs with password strength feedback |
| 📦 **Keyring** | `Alt+4` | Browse, search, sort, import/export, and delete keys |
| 👥 **Contacts** | `Alt+5` | Add contacts, link keys, search and edit |
| ✍️ **Sign** | `Alt+6` | Sign files or messages with Ed25519, RSA, or PGP |
| ✅ **Verify** | `Alt+7` | Verify signatures against public keys |
| 🔒 **PassGen** | `Alt+8` | Generate random passwords and passphrases |
| 💬 **Messaging** | `Alt+9` | Secure end-to-end encrypted messaging |
| 📱 **QR Exchange** | — | Share public keys via QR code URIs |
| ⚙️ **Settings** | — | Default algorithm, theme, preferences |
| 📋 **Audit Log** | `Alt+0` | Browse and verify the audit trail |
| 💾 **Backup** | — | Create, verify, and restore keystore backups |

**Tips:**
- Use `Ctrl+F` to focus the search box in Keyring or Contacts
- Use `Ctrl+R` to refresh the current view
- Toast notifications confirm success/error after operations
- Your window size, theme, and preferences are saved automatically

---

## Common Workflows

### Password-Based File Encryption

```bash
# Encrypt
hb-zayfer encrypt document.pdf -p

# Decrypt
hb-zayfer decrypt document.pdf.hbzf
```

### Public-Key Encryption (Send to Someone)

```bash
# 1. Import their public key
hb-zayfer keys import alice_key.pem --label "Alice" --algorithm ed25519

# 2. Add as a contact and link the key
hb-zayfer contacts add "Alice" --email alice@example.com
hb-zayfer contacts link "Alice" <alice-fingerprint-prefix>

# 3. Encrypt for Alice
hb-zayfer encrypt message.txt --recipient alice

# 4. Send message.txt.hbzf — only Alice can decrypt it
```

### Digital Signatures

```bash
# Generate a signing key
hb-zayfer keygen ed25519 --label "My Signing Key"

# Sign a file
hb-zayfer sign document.pdf --key <fingerprint-prefix>
# Creates: document.pdf.sig

# Verify a signature (recipient needs your public key)
hb-zayfer verify document.pdf document.pdf.sig --key <signer-fingerprint>
```

### Backup Your Keys

```bash
# Create encrypted backup
hb-zayfer backup create -o ~/backups/keys-$(date +%Y%m%d).hbzf

# Verify backup integrity
hb-zayfer backup verify -i ~/backups/keys-$(date +%Y%m%d).hbzf

# Restore if needed (overwrites current keystore)
hb-zayfer backup restore -i ~/backups/keys-$(date +%Y%m%d).hbzf
```

### Generate Secure Passwords

```bash
# Random 24-character password
hb-zayfer passgen --length 24

# 6-word passphrase with dashes
hb-zayfer passgen --words 6 --separator "-"

# Exclude ambiguous characters
hb-zayfer passgen --length 20 --exclude "0O1lI"
```

### Shamir's Secret Sharing

```bash
# Split a master passphrase into 5 shares (need 3 to reconstruct)
hb-zayfer shamir split --shares 5 --threshold 3 --secret "master passphrase"

# Combine any 3 shares to recover the secret
hb-zayfer shamir combine --shares <hex1>,<hex2>,<hex3>
```

### Batch Directory Encryption

```bash
# Encrypt all files in a directory
hb-zayfer encrypt-dir ./sensitive-docs -p

# Decrypt all .hbzf files in a directory
hb-zayfer decrypt-dir ./sensitive-docs
```

### Secure File Deletion

```bash
# Securely shred a file (3 passes of random overwrite)
hb-zayfer shred secret.txt --passes 3

# Recursively shred a directory
hb-zayfer shred ./temp-secrets --recursive
```

### QR Code Key Exchange

```bash
# In the GUI: Navigate to QR Exchange view
# Enter a key fingerprint and label → generates a QR-ready URI
# Share the URI or QR image with your contact
```

---

## CLI Cheat Sheet

```bash
# KEY MANAGEMENT
hb-zayfer keygen ed25519 --label "MyKey"       # Generate signing key
hb-zayfer keygen x25519 --label "MyKey"        # Generate encryption key
hb-zayfer keygen rsa4096 --label "MyKey"       # Generate RSA key
hb-zayfer keygen pgp --label "MyKey" -u "Name <email>"  # Generate PGP key
hb-zayfer keys list                            # List all keys
hb-zayfer keys list --json                     # List keys (JSON output)
hb-zayfer keys export <fp> -o key.pub          # Export public key
hb-zayfer keys import key.pub -l "Name" -a ed25519   # Import public key
hb-zayfer keys delete <fp>                     # Delete key

# ENCRYPTION / DECRYPTION
hb-zayfer encrypt file.txt -p                  # Password encryption
hb-zayfer encrypt file.txt -p -a chacha        # With ChaCha20
hb-zayfer encrypt file.txt -r alice            # Recipient encryption
hb-zayfer decrypt file.txt.hbzf               # Decrypt (auto-detect)
hb-zayfer decrypt file.txt.hbzf -k <fp>       # Decrypt with specific key
hb-zayfer encrypt-dir ./docs -p               # Batch encrypt directory
hb-zayfer decrypt-dir ./docs                  # Batch decrypt directory
hb-zayfer inspect file.txt.hbzf               # Inspect HBZF metadata

# SIGNING / VERIFICATION
hb-zayfer sign file.txt -k <fp>               # Sign with Ed25519
hb-zayfer sign file.txt -k <fp> -a rsa        # Sign with RSA
hb-zayfer verify file.txt file.sig -k <fp>    # Verify signature

# CONTACTS
hb-zayfer contacts add "Alice" -e alice@example.com  # Add contact
hb-zayfer contacts link "Alice" <fp>           # Link key to contact
hb-zayfer contacts list                        # List contacts
hb-zayfer contacts remove "Alice"              # Remove contact

# BACKUP & AUDIT
hb-zayfer backup create -o backup.hbzf         # Create backup
hb-zayfer backup verify -i backup.hbzf         # Verify backup
hb-zayfer backup restore -i backup.hbzf        # Restore backup
hb-zayfer audit show                           # Show audit log
hb-zayfer audit verify                         # Verify integrity
hb-zayfer audit export -o audit.json           # Export audit log

# SECURITY TOOLS
hb-zayfer passgen --length 24                  # Generate password
hb-zayfer passgen --words 6                    # Generate passphrase
hb-zayfer shred secret.txt -p 3               # Secure file shred
hb-zayfer shred ./dir -r                      # Recursive directory shred
hb-zayfer shamir split -n 5 -t 3 -s "secret"  # Split secret
hb-zayfer shamir combine -s <hex1>,<hex2>,...  # Combine shares

# CONFIGURATION
hb-zayfer config list                          # Show all settings
hb-zayfer config set default_algorithm chacha  # Change default
hb-zayfer config get default_algorithm         # Read setting
hb-zayfer completions bash                     # Shell completions
```

---

## Next Steps

### For End Users
1. [USER_GUIDE.md](USER_GUIDE.md) — Complete feature documentation
2. [SECURE_COMMUNICATIONS.md](SECURE_COMMUNICATIONS.md) — Encryption best practices tutorial
3. [CLI.md](CLI.md) — Full CLI command reference

### For Developers
1. [ARCHITECTURE.md](ARCHITECTURE.md) — System design overview
2. [PYTHON_API.md](PYTHON_API.md) — Python API reference
3. [CONTRIBUTING.md](CONTRIBUTING.md) — Development guide

### For Security Teams
1. [SECURITY.md](SECURITY.md) — Security model and threat analysis
2. [HBZF_FORMAT.md](HBZF_FORMAT.md) — Binary file format specification
3. [TECHNICAL_REFERENCE.md](TECHNICAL_REFERENCE.md) — Algorithm and implementation details

---

## Important Security Notes

- **Passphrases cannot be recovered** — choose strong passphrases and remember them
- **Back up your keystore** — without backups, lost keys means lost access to encrypted files
- **Verify key fingerprints** — always verify public keys through a separate secure channel
- **Keep software updated** — check for updates regularly
- **Use the password generator** — `hb-zayfer passgen` creates cryptographically secure passwords

---

**Ready to learn more?** Continue with the [User Guide](USER_GUIDE.md).
