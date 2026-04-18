# Technical Reference

**Zayfer Vault v1.0.1**

Compact reference card for all algorithms, CLI commands, Python functions,
REST endpoints, configuration keys, and file formats.

---

## Algorithm Parameters

### AES-256-GCM

| Parameter | Value |
|-----------|-------|
| Key size | 256 bits (32 bytes) |
| Nonce | 96 bits (12 bytes), random per operation |
| Tag | 128 bits (16 bytes), appended to ciphertext |
| AAD | Arbitrary (can be empty) |

### ChaCha20-Poly1305

| Parameter | Value |
|-----------|-------|
| Key size | 256 bits (32 bytes) |
| Nonce | 96 bits (12 bytes), random per operation |
| Tag | 128 bits (16 bytes), appended to ciphertext |

### RSA

| Variant | Key size | Padding |
|---------|----------|---------|
| Encrypt | 2048 or 4096 | OAEP-SHA256-MGF1 |
| Sign | 2048 or 4096 | PSS-SHA256 (salt len = hash len) |

### Ed25519

| Parameter | Value |
|-----------|-------|
| Signature | 64 bytes |
| Public key | 32 bytes |
| Private key | 64 bytes (seed + public) |

### X25519

| Parameter | Value |
|-----------|-------|
| Secret key | 32 bytes |
| Public key | 32 bytes |
| Shared secret | 32 bytes (HKDF-SHA256 derived) |

### Argon2id Defaults

| Preset | Memory | Time | Parallelism |
|--------|--------|------|-------------|
| Low | 16 MiB | 2 | 1 |
| Standard | 64 MiB | 3 | 1 |
| High | 256 MiB | 4 | 2 |
| Paranoid | 1 GiB | 6 | 4 |

### scrypt Defaults

| Parameter | Default | Description |
|-----------|---------|-------------|
| `log_n` | 15 | log₂(N), N = 32768 |
| `r` | 8 | Block size |
| `p` | 1 | Parallelism |

---

## HBZF File Format

```
Offset  Field            Size
──────  ───────────────  ──────────────────────
0x00    Magic            4 B   "HBZF"
0x04    Version          1 B   u8 (0x01)
0x05    Algorithm        1 B   0x01=AES, 0x02=ChaCha
0x06    Key wrapping     1 B   0x01=Password, 0x02=RSA, 0x03=X25519
0x08    KDF params       var   (salt + cost params if password-wrapped)
var     Wrapped key      var   (encrypted DEK or ephemeral public)
var     Nonce            12 B
var     Ciphertext+Tag   var   (may be compressed; see compression flag)
```

The compressed payload uses a 1-byte prefix: `0x00` = stored, `0x01` = deflate.

---

## CLI Command Quick Reference

### Core Commands

| Command | Description |
|---------|-------------|
| `hb-zayfer keygen <algo>` | Generate key pair (rsa-2048/rsa-4096/ed25519/x25519/pgp) |
| `hb-zayfer encrypt -i FILE -o OUT` | Encrypt a file |
| `hb-zayfer decrypt -i FILE -o OUT` | Decrypt a file |
| `hb-zayfer sign -i FILE -k FP` | Sign a file |
| `hb-zayfer verify -i FILE -s SIG -k FP` | Verify a signature |
| `hb-zayfer keys` | List stored keys |
| `hb-zayfer contacts` | Manage contacts (add/list/remove/link) |

### Extended Commands

| Command | Description |
|---------|-------------|
| `hb-zayfer encrypt-dir -i DIR -o DIR` | Encrypt all files in directory |
| `hb-zayfer decrypt-dir -i DIR -o DIR` | Decrypt all `.hbzf` files in directory |
| `hb-zayfer inspect FILE` | Show HBZF header metadata |
| `hb-zayfer shred FILE [--passes N]` | Securely overwrite and delete |
| `hb-zayfer passgen [--length N]` | Generate random password |
| `hb-zayfer passgen --passphrase [--words N]` | Generate diceware passphrase |
| `hb-zayfer shamir split SECRET -s N -t K` | Split secret into shares |
| `hb-zayfer shamir combine --shares S1,S2,...` | Reconstruct from shares |

### Management Commands

| Command | Description |
|---------|-------------|
| `hb-zayfer backup create -o FILE` | Create encrypted backup |
| `hb-zayfer backup restore -i FILE` | Restore from backup |
| `hb-zayfer backup verify -i FILE` | Verify backup integrity |
| `hb-zayfer audit` | Show recent audit entries |
| `hb-zayfer audit verify` | Verify audit chain integrity |
| `hb-zayfer audit export -o FILE` | Export audit log |
| `hb-zayfer config list` | Show all settings |
| `hb-zayfer config get KEY` | Get a setting |
| `hb-zayfer config set KEY VALUE` | Set a setting |
| `hb-zayfer config reset` | Reset to defaults |
| `hb-zayfer config path` | Show config file path |
| `hb-zayfer completions SHELL` | Generate shell completions |

### Global Flags

| Flag | Description |
|------|-------------|
| `--json` | Output in JSON format |
| `--passphrase-file FILE` | Read passphrase from file |
| `--help` / `-h` | Show help |

---

## Python Function Quick Reference

### Symmetric

| Function | Returns |
|----------|---------|
| `aes_encrypt(key, pt, aad)` | `(nonce, ct)` |
| `aes_decrypt(key, nonce, ct, aad)` | `bytes` |
| `chacha_encrypt(key, pt, aad)` | `(nonce, ct)` |
| `chacha_decrypt(key, nonce, ct, aad)` | `bytes` |

### KDF

| Function | Returns |
|----------|---------|
| `generate_salt(length)` | `bytes` |
| `derive_key_argon2(pass, salt, ...)` | `bytes` (32) |
| `derive_key_scrypt(pass, salt, ...)` | `bytes` (32) |

### RSA

| Function | Returns |
|----------|---------|
| `rsa_generate(bits)` | `(priv_pem, pub_pem)` |
| `rsa_encrypt(pub_pem, pt)` | `bytes` |
| `rsa_decrypt(priv_pem, ct)` | `bytes` |
| `rsa_sign(priv_pem, msg)` | `bytes` |
| `rsa_verify(pub_pem, msg, sig)` | `bool` |
| `rsa_fingerprint(pub_pem)` | `str` |

### Ed25519

| Function | Returns |
|----------|---------|
| `ed25519_generate()` | `(sign_pem, ver_pem)` |
| `ed25519_sign(sign_pem, msg)` | `bytes` |
| `ed25519_verify(ver_pem, msg, sig)` | `bool` |
| `ed25519_fingerprint(ver_pem)` | `str` |

### X25519

| Function | Returns |
|----------|---------|
| `x25519_generate()` | `(secret, public)` |
| `x25519_encrypt_key_agreement(their_pub)` | `(eph, key)` |
| `x25519_decrypt_key_agreement(secret, eph)` | `bytes` |
| `x25519_fingerprint(public)` | `str` |

### OpenPGP

| Function | Returns |
|----------|---------|
| `pgp_generate(user_id)` | `(pub, sec)` |
| `pgp_encrypt(pt, pubkeys)` | `bytes` |
| `pgp_decrypt(ct, seckey)` | `bytes` |
| `pgp_sign(msg, seckey)` | `bytes` |
| `pgp_verify(signed, pubkey)` | `(bytes, bool)` |
| `pgp_fingerprint(armored)` | `str` |
| `pgp_user_id(armored)` | `Optional[str]` |

### HBZF Format

| Function | Returns |
|----------|---------|
| `encrypt_data(pt, algo, wrap, ...)` | `bytes` |
| `decrypt_data(data, ...)` | `bytes` |
| `encrypt_file(in, out, ...)` | `int` |
| `decrypt_file(in, out, ...)` | `int` |

### Password Generation

| Function | Returns |
|----------|---------|
| `generate_password(length, exclude)` | `str` |
| `generate_passphrase(words, separator)` | `str` |
| `password_entropy(length)` | `float` |
| `passphrase_entropy(words)` | `float` |

### Shamir SSS

| Function | Returns |
|----------|---------|
| `shamir_split(secret, shares, threshold)` | `list[str]` |
| `shamir_combine(shares)` | `bytes` |

### Steganography

| Function | Returns |
|----------|---------|
| `stego_embed(image_data, message)` | `bytes` |
| `stego_extract(stego_data)` | `bytes` |
| `stego_capacity(image_data)` | `int` |

### Secure Shred

| Function | Returns |
|----------|---------|
| `shred_file(path, passes)` | `None` |
| `shred_directory(path, passes)` | `None` |

### QR Exchange

| Function | Returns |
|----------|---------|
| `qr_encode_key_uri(algo, fp, label)` | `str` |
| `qr_decode_key_uri(uri)` | `(str, str, Optional[str])` |

### Utilities

| Function | Returns |
|----------|---------|
| `compute_fingerprint(key_bytes)` | `str` |
| `detect_key_format(data)` | `str` |
| `version()` | `str` |

---

## REST API Quick Reference (30 Endpoints)

All endpoints prefixed with `/api`.

| Method | Endpoint | Body |
|--------|----------|------|
| GET | `/version` | — |
| POST | `/encrypt/text` | JSON |
| POST | `/decrypt/text` | JSON |
| POST | `/encrypt/file` | Multipart |
| POST | `/decrypt/file` | Multipart |
| POST | `/keygen` | JSON |
| GET | `/keys` | — |
| DELETE | `/keys/{fp}` | — |
| GET | `/keys/{fp}/public` | — |
| GET | `/contacts` | — |
| POST | `/contacts` | JSON |
| DELETE | `/contacts/{name}` | — |
| POST | `/contacts/link` | JSON |
| POST | `/sign` | JSON |
| POST | `/verify` | JSON |
| GET | `/audit/recent` | — |
| GET | `/audit/verify` | — |
| GET | `/audit/count` | — |
| POST | `/audit/export` | Query |
| POST | `/backup/create` | JSON |
| POST | `/backup/verify` | JSON |
| POST | `/backup/restore` | JSON |
| GET | `/config` | — |
| GET | `/config/{key}` | — |
| PUT | `/config/{key}` | JSON |
| POST | `/passgen` | JSON |
| POST | `/shamir/split` | JSON |
| POST | `/shamir/combine` | JSON |
| POST | `/qr/encode` | JSON |
| POST | `/qr/decode` | JSON |

---

## Configuration Keys

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `default_algorithm` | string | `"aes"` | `"aes"` or `"chacha"` |
| `default_kdf` | string | `"standard"` | `"low"`, `"standard"`, `"high"`, `"paranoid"` |
| `gui.theme` | string | `"dark"` | `"dark"`, `"light"`, `"auto"` |
| `gui.font_size` | float | `13.0` | GUI font size in points |
| `gui.confirm_shred` | bool | `true` | Require confirmation before shredding |
| `cli.color` | bool | `true` | Coloured terminal output |
| `cli.json_output` | bool | `false` | Default to JSON output |

---

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `HB_ZAYFER_HOME` | `~/.hb_zayfer/` | Override the default data directory for keys, contacts, audit data, and config |
| `HB_ZAYFER_API_TOKEN` | *(unset)* | Require `Authorization: Bearer <token>` on web API requests |
| `HB_ZAYFER_RATE_LIMIT` | `60` | Maximum requests per client IP in each rate-limit window |
| `HB_ZAYFER_RATE_WINDOW` | `60` | Rate-limit window duration in seconds |
| `HB_ZAYFER_PORT` | `8000` | Default web-server port when launching `./run.sh web` |
| `HB_ZAYFER_SKIP_ONBOARDING` | *(unset)* | Skip the GUI first-run prompt for CI/headless smoke tests |

---

## Data Directory Layout

| Path | Contents |
|------|----------|
| `~/.hb_zayfer/` | Default data directory |
| `~/.hb_zayfer/keys/private/` | Encrypted private keys |
| `~/.hb_zayfer/keys/public/` | Public key material |
| `~/.hb_zayfer/keyring.json` | Key metadata index |
| `~/.hb_zayfer/contacts.json` | Contact database |
| `~/.hb_zayfer/audit.json` | Tamper-evident audit trail |
| `~/.hb_zayfer/config.toml` | Core CLI/runtime configuration |
| `~/.hb_zayfer/config.json` | Web/GUI configuration |
| `~/.hb_zayfer/gui_settings.json` | Persisted window and interface settings |

---

## Operational Commands

| Task | Command |
|------|---------|
| Launch GUI | `./run.sh` or `./run.sh gui` |
| Launch web UI | `./run.sh web` |
| Show CLI help | `./run.sh cli --help` |
| Rebuild native extension | `./run.sh build` |
| Run the full supported verification set | `HB_ZAYFER_SKIP_ONBOARDING=1 QT_QPA_PLATFORM=offscreen ./run.sh test` |
