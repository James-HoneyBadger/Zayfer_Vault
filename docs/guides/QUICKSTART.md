# Quick Start Guide

Get Zayfer Vault running quickly with the **current Rust-first launcher**.

---

## 1. Requirements

- Linux, macOS, or Windows
- Rust 1.75+
- Python 3.10+ for the desktop GUI and bindings

### Linux packages

On Ubuntu or Debian, install:

```bash
sudo apt-get update
sudo apt-get install -y pkg-config libssl-dev nettle-dev build-essential python3-venv libxcb-cursor0
```

`libxcb-cursor0` is especially important for the Qt desktop GUI on Linux.

---

## 2. Recommended setup

```bash
git clone https://github.com/James-HoneyBadger/Zayfer_Vault.git
cd Zayfer_Vault
./run.sh doctor
```

Then launch the interface you want:

```bash
./run.sh gui
./run.sh web
./run.sh cli --help
```

The launcher creates the virtual environment, builds the native extension when needed, and routes web and CLI modes through Rust.

---

## 3. First encrypted file

```bash
echo "My secret message" > secret.txt

./run.sh cli encrypt \
  --input secret.txt \
  --output secret.txt.hbzf \
  --password

./run.sh cli decrypt \
  --input secret.txt.hbzf \
  --output secret.txt

cat secret.txt
```

---

## 4. First key pair

```bash
./run.sh cli keygen --algorithm ed25519 --label "My First Key"
./run.sh cli keys list
./run.sh cli keys export <fingerprint> --output my_public_key.pem
```

Your key material and config are stored under `~/.hb_zayfer/` unless you override the path with `HB_ZAYFER_HOME`.

---

## 5. Launch the desktop GUI

```bash
./run.sh gui
```

The GUI provides sidebar workflows for:

- Encrypt / Decrypt
- Key generation and keyring management
- Contacts
- Sign / Verify
- Password generation
- Audit and backup
- Settings and QR exchange helpers

---

## 6. Launch the browser UI

```bash
./run.sh web
```

Open `http://127.0.0.1:8000/` in your browser.

The current browser UI is served by the Rust-native web runtime, while the older Python web app remains available as a compatibility path.

---

## 7. Useful commands

```bash
# Sign and verify
./run.sh cli sign --input document.pdf --key <fingerprint> --output document.pdf.sig
./run.sh cli verify --input document.pdf --signature document.pdf.sig --key <fingerprint>

# Backup and audit
./run.sh cli backup create --output backup.hbzf
./run.sh cli backup verify --input backup.hbzf
./run.sh cli audit show --limit 10

# Utilities
./run.sh cli passgen --length 24
./run.sh cli shamir split "master secret" --shares 5 --threshold 3
./run.sh cli shred secret.txt --passes 3
```

---

## Next steps

1. Read [CLI.md](../reference/CLI.md) for the full Rust command reference.
2. Open [WEB_GUI.md](WEB_GUI.md) for desktop and web runtime details.
3. Use [USER_GUIDE.md](USER_GUIDE.md) for daily workflows and operational guidance.

