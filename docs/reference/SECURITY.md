# Security Design & Audit Notes

**Zayfer Vault v1.1.0**

This document details the security posture of Zayfer Vault: algorithms chosen,
key management practices, memory protections, supply-chain considerations,
and known limitations.

---

## Cryptographic Algorithms

| Category | Algorithm | Standard | Key Size |
|----------|-----------|----------|----------|
| Symmetric (AEAD) | AES-256-GCM | NIST SP 800-38D | 256-bit |
| Symmetric (AEAD) | ChaCha20-Poly1305 | RFC 8439 | 256-bit |
| KDF | Argon2id | RFC 9106 | Configurable |
| KDF | scrypt | RFC 7914 | Configurable |
| Asymmetric Enc. | RSA-OAEP-SHA256 | PKCS#1 v2.2 | 2048/4096-bit |
| Signatures | RSA-PSS-SHA256 | PKCS#1 v2.1 | 2048/4096-bit |
| Signatures | Ed25519 | RFC 8032 | 256-bit curve |
| Key Agreement | X25519 | RFC 7748 | 256-bit curve |
| OpenPGP | Sequoia PGP | RFC 4880/6637 | Per key type |
| Secret Sharing | Shamir SSS GF(2⁸) | Shamir (1979) | ≤ 255 shares |
| Hashing | SHA-256 | FIPS 180-4 | 256-bit |

All nonces / IVs are generated from `OsRng` (kernel CSPRNG).

---

## Key Derivation Defaults

| Preset | Argon2id m\_cost | t\_cost | p\_cost | Notes |
|--------|-----------------|---------|---------|-------|
| Low | 16 MiB | 2 | 1 | Interactive / embedded |
| Standard | 64 MiB | 3 | 1 | Default for most uses |
| High | 256 MiB | 4 | 2 | High-value keys |
| Paranoid | 1 GiB | 6 | 4 | Maximum strength |

The `config` module exposes `KdfPreset` for easy switching. CLI and GUI
default to **Standard**.

---

## Memory Security

### `SecureBytes`

All sensitive key material is stored in `SecureBytes` buffers:

- **`mlock(2)`** — Pages are locked in physical RAM, preventing swap-out
- **Zeroize-on-drop** — `zeroize` crate blanks memory before deallocation
- **Redacted `Debug`** — `Debug` output prints only `len` and `locked`, never
  the contents
- **`munlock(2)` on drop** — Memory is unlocked after zeroizing

### Passphrase Handling

Passphrases are accepted as `&[u8]` and immediately converted to `SecureBytes`
within the Rust core. No string copies are retained after key derivation.

---

## Secure File Shredding

The `shred` module performs multi-pass file overwrite before deletion:

1. **Random pass** — Overwrite entire file with cryptographic random bytes
2. **Zero pass** — Overwrite with `0x00`
3. **Random pass** — Final random overwrite
4. Repeat for the configured number of passes (default: 3)
5. **Truncate** to zero length
6. **`fsync()`** — Flush to disk
7. **`unlink()`** — Remove directory entry

**Limitations:**

- Journaling filesystems (ext4, NTFS) may retain journal copies
- SSD wear-levelling may keep old data in unmapped sectors
- Copy-on-write filesystems (ZFS, btrfs) create new blocks on write
- For maximum security on SSDs, combine with full-disk encryption (LUKS/dm-crypt)

---

## Audit Logging

### Hash-Chain Integrity

Each audit entry includes:

- `entry_hash = SHA-256(timestamp ‖ operation ‖ prev_hash ‖ note)`
- `prev_hash` — Hash of the immediately preceding entry

This creates a tamper-evident append-only log:

```
Entry 0:  hash₀ = H(ts₀ ‖ op₀ ‖ ∅ ‖ note₀)
Entry 1:  hash₁ = H(ts₁ ‖ op₁ ‖ hash₀ ‖ note₁)
Entry 2:  hash₂ = H(ts₂ ‖ op₂ ‖ hash₁ ‖ note₂)
...
```

`verify_integrity()` replays the entire chain and checks every hash.

### What Is Logged

| Operation | Fields Recorded |
|-----------|----------------|
| Key generated | Algorithm, fingerprint |
| File encrypted | Algorithm, filename, size |
| File decrypted | Algorithm, filename, size |
| Data signed | Algorithm, signer fingerprint |
| Signature verified | Algorithm, signer fingerprint, valid/invalid |
| Contact added | Contact name |
| Contact deleted | Contact name |
| Key deleted | Fingerprint |

---

## Key Storage Security

### At-Rest Encryption

Private keys stored in the `KeyStore` are encrypted at rest:

1. User provides a passphrase for each private key
2. Salt is generated (32 bytes, `OsRng`)
3. Key derived via Argon2id (Standard preset)
4. Private key bytes encrypted with AES-256-GCM
5. Stored as: `salt ‖ nonce ‖ ciphertext_with_tag`

Public keys are stored as plaintext (they are public).

### Key Usage Constraints

Keys can be tagged with a `KeyUsage` policy:

- `Encrypt` — Key may be used for encryption / key wrapping
- `Decrypt` — Key may be used for decryption / key unwrapping
- `Sign` — Key may be used for digital signatures
- `Verify` — Key may be used for signature verification
- `KeyAgreement` — Key may be used for Diffie-Hellman key agreement

### Key Expiry

Keys can have an optional `expires_at` timestamp. The `KeyExpiryStatus` enum
reports:

- `NoExpiry` — No expiration set
- `Valid { expires_at }` — Key is within validity period
- `Expired { expired_at }` — Key has expired

Expired keys can still be read (for decryption of old data) but the GUI/CLI
warn when selecting them.

---

## Shamir's Secret Sharing

The `shamir` module implements byte-level Shamir's Secret Sharing over GF(2⁸):

- **Threshold scheme**: any _k_ of _n_ shares reconstruct the secret;
  fewer than _k_ shares reveal zero information
- **Constraints**: 2 ≤ _k_ ≤ _n_ ≤ 255
- **Security**: Information-theoretically secure — no computational
  assumptions beyond the GF(2⁸) arithmetic
- **Use case**: Split a master passphrase or key among multiple custodians
  for disaster recovery

---

## Steganography

The `stego` module provides LSB (Least Significant Bit) embedding in raw
pixel data:

- **Encoding**: 1 bit per pixel byte, with a 64-bit length header
- **Capacity**: `pixel_count / 8 - 8` bytes
- **Security note**: LSB steganography is detectable via statistical analysis
  (chi-square, RS analysis). Use for casual concealment, not against a
  determined adversary. For strong confidentiality, encrypt data first, then
  embed the ciphertext.

---

## QR Key Exchange

`hbzf-key://` URIs encode a public key reference:

```
hbzf-key://<algorithm>/<base64url-encoded-key>?label=<label>
```

- URI does **not** contain private key material
- Designed for in-person key exchange (phone-to-phone QR scan)
- Base64url encoding avoids QR-unfriendly characters

---

## Web API Security

### Rate Limiting

The web server includes a built-in `_RateLimiter` that caps requests per
client IP. Configuration via environment variables:

| Variable | Default | Description |
|----------|---------|-------------|
| `HB_ZAYFER_RATE_LIMIT` | `60` | Maximum requests per window |
| `HB_ZAYFER_RATE_WINDOW` | `60` | Window duration in seconds |

For production deployments you should **also**:

- Use a reverse proxy (nginx, Caddy) with additional rate-limit rules
- Bind to `127.0.0.1` (default) — do not expose to the public internet
  without TLS and authentication

### Authentication

The web server supports optional Bearer-token authentication. Set the
`HB_ZAYFER_API_TOKEN` environment variable to enable it:

```bash
export HB_ZAYFER_API_TOKEN="my-secret-token"
```

When set, every request must include an `Authorization: Bearer <token>` header.
When unset, the server runs without authentication (suitable for local use).

For multi-user or internet-facing deployments, add:

- TLS termination (nginx/Caddy)
- Additional auth layers at the reverse proxy if needed

---

## Compression Security

Optional deflate compression is applied inside the HBZF container:

- Compression happens **before** encryption (compress-then-encrypt)
- A 1-byte magic header (`0x01` = compressed, `0x00` = stored) is included
  inside the encrypted payload, so an attacker cannot determine whether
  compression was used
- **CRIME/BREACH note**: Compression of secret data alongside attacker-
  controlled data can leak information via ciphertext length. Zayfer Vault's
  HBZF format does not mix user-controlled AAD into the compressed payload,
  mitigating this vector. However, file-size side channels remain for any
  encrypted format.

---

## Supply Chain

### Dependencies

All cryptographic operations are performed by audited, widely-used Rust crates:

| Crate | Version | Purpose |
|-------|---------|---------|
| `aes-gcm` | 0.10 | AES-256-GCM |
| `chacha20poly1305` | 0.10 | ChaCha20-Poly1305 |
| `argon2` | 0.5 | Argon2id KDF |
| `scrypt` | 0.11 | scrypt KDF |
| `rsa` | 0.9 | RSA |
| `ed25519-dalek` | 2.1 | Ed25519 |
| `x25519-dalek` | 2.0 | X25519 |
| `sequoia-openpgp` | 2.x | OpenPGP |
| `sha2` | 0.10 | SHA-256 |
| `rand` / `rand_core` | 0.8 | CSPRNG (`OsRng`) |
| `zeroize` | 1.x | Secure memory zeroization |
| `flate2` | 1.x | Deflate compression |

No custom cryptographic primitives are implemented.

### Build Reproducibility

- `Cargo.lock` is committed for reproducible builds
- `maturin` wheel builds are pinned via `pyproject.toml`
- CI should verify `cargo audit` for known vulnerabilities

---

## Known Limitations

1. **No forward secrecy** for password-wrapped HBZF files — the same
   passphrase always derives the same key for a given salt
2. **File-size side channel** — encrypted file size reveals approximate
   plaintext size (± compression ratio)
3. **No built-in secure transport** — the web API serves over HTTP; TLS
   must be provided externally
4. **SSD shredding** — `shred_file` cannot guarantee erasure on
   wear-levelled storage (see Secure File Shredding section)
5. **LSB stego is detectable** — use encryption before embedding for
   confidentiality
6. **OpenPGP passphrase** — Sequoia-generated secret keys are not
   passphrase-protected at the PGP layer; they rely on KeyStore encryption

---

## Reporting Vulnerabilities

Please report security issues via GitHub private vulnerability disclosure
or email the maintainer directly. Do not open public issues for security bugs.
