# Tutorial: Encryption, Decryption, and Password Hygiene

A practical, security-first walkthrough for Zayfer Vault users.

**Audience:** first-time users, operators, and anyone who wants a safe workflow for protecting files, messages, and passwords.

---

## What You Will Learn

By the end of this tutorial, you will be able to:

1. choose between **password-based** and **recipient-based** encryption,
2. create a **strong password or passphrase**,
3. **encrypt and decrypt** files and text using the GUI, CLI, and Python API,
4. understand when to **sign** data in addition to encrypting it, and
5. avoid common mistakes that lead to lost access or weak security.

---

## 1) Choose the Right Protection Model

Before you encrypt anything, decide **who needs to decrypt it later**.

| Use case | Best option | Why |
|---|---|---|
| You alone need access | **Password-based encryption** | Simple and portable |
| You are sending to another person | **Recipient/public-key encryption** | No shared secret has to travel with the file |
| You need both privacy and proof of origin | **Encrypt + sign** | Protects confidentiality and authenticity |

> **Rule of thumb:** if you would otherwise send the password in the same chat or email as the file, use **recipient-based encryption** instead.

---

## 2) Make a Strong Password or Passphrase

### Good password rules

- Use a **password manager** whenever possible.
- Prefer **16+ random characters** or a **5–7 word passphrase**.
- Never reuse a password from email, banking, work, or another service.
- Do not store the password in the same folder as the encrypted file.

### Built-in password generation

#### GUI
1. Open **`🔐 PassGen`**.
2. Choose **Password** or **Passphrase**.
3. Adjust length or word count.
4. Copy the generated value into your password manager.

#### CLI

```bash
# Random 24-character password
hb-zayfer passgen --length 24

# 6-word passphrase
hb-zayfer passgen --words 6 --separator "-"

# Exclude ambiguous characters
hb-zayfer passgen --length 20 --exclude "0O1lI"
```

---

## 3) Encrypt a File with a Password

Create a sample file:

```bash
echo "Quarterly financial draft" > secret.txt
```

### GUI workflow

1. Start the app with `./run.sh`.
2. Open **`🔐 Encrypt`**.
3. Select your input file.
4. Choose `AES-256-GCM` or `ChaCha20-Poly1305`.
5. Select **Password** mode.
6. Enter and confirm the password.
7. Click **Encrypt**.

Output: a new `secret.txt.hbzf` file.

### CLI workflow

```bash
# Encrypt using the default algorithm
hb-zayfer encrypt secret.txt -p

# Encrypt with ChaCha20-Poly1305 instead of AES
hb-zayfer encrypt secret.txt -p -a chacha
```

### Python workflow

```python
import hb_zayfer as hbz

plaintext = b"Quarterly financial draft"
encrypted = hbz.encrypt_data(
    plaintext,
    algorithm="aes",
    wrapping="password",
    passphrase=b"correct horse battery staple",
)
print(f"Encrypted {len(plaintext)} bytes into {len(encrypted)} bytes")
```

---

## 4) Decrypt the File

### GUI workflow

1. Open **`🔓 Decrypt`**.
2. Select the `.hbzf` file.
3. Enter the same password.
4. Click **Decrypt**.

### CLI workflow

```bash
hb-zayfer decrypt secret.txt.hbzf
```

### Python workflow

```python
decrypted = hbz.decrypt_data(
    encrypted,
    passphrase=b"correct horse battery staple",
)
assert decrypted == plaintext
```

### Verify the result

Always verify that the decrypted output is exactly what you expected:

- open the file and inspect it,
- confirm the filename and extension,
- compare hashes for important files if needed.

---

## 5) Encrypt for Another Person

Use recipient-based encryption when sending data to someone else.

### Basic flow

1. Obtain the recipient’s **public key**.
2. Verify its **fingerprint** through a separate channel.
3. Import the key.
4. Associate it with a contact.
5. Encrypt using that recipient.

### CLI example

```bash
# Import Alice's public key
hb-zayfer keys import alice_pub.pem --label "Alice" --algorithm x25519

# Add a contact record
hb-zayfer contacts add "Alice" --email alice@example.com
hb-zayfer contacts link "Alice" <alice-fingerprint>

# Encrypt for Alice
hb-zayfer encrypt message.txt --recipient alice
```

### Why this is safer

With public-key encryption:

- you do **not** need to share a password for the file,
- only the holder of the matching private key can decrypt,
- the encrypted file can travel over email or chat without exposing a shared secret.

---

## 6) Add a Signature When Authenticity Matters

Encryption hides the content. A signature proves who created it.

Use signatures for:

- contracts,
- release artifacts,
- audit exports,
- instructions or scripts you send to someone else.

### CLI example

```bash
# Sign a file
hb-zayfer sign document.pdf --key <your-signing-key>

# Verify it later
hb-zayfer verify document.pdf document.pdf.sig --key <your-public-key>
```

> **Best practice:** use **Ed25519** for signatures unless you need RSA or PGP interoperability.

---

## 7) Recommended Password Practices

### Do

- store secrets in a **password manager**,
- back up the password manager and the Zayfer Vault keystore separately,
- use a **different passphrase** for encrypted backups,
- rotate passwords if you suspect exposure.

### Don’t

- reuse passwords,
- put passwords in shell history or shared notes,
- name text files `passwords.txt`,
- assume encryption alone proves who sent a file.

---

## 8) Recovery and Safety Checklist

Before you rely on the tool for important data, complete this checklist:

- [ ] I created at least one backup with `hb-zayfer backup create`.
- [ ] I verified the backup with `hb-zayfer backup verify`.
- [ ] I tested decryption on a non-critical file.
- [ ] I know whether my workflow uses **password** or **recipient** encryption.
- [ ] I stored my passphrase in a safe place.
- [ ] I verified key fingerprints before trusting imported public keys.

---

## 9) Common Mistakes

| Mistake | Why it is dangerous | Better approach |
|---|---|---|
| Sending the password in the same message as the file | Breaks the security model | Use recipient-based encryption or a different channel |
| Reusing a personal password | Increases breach impact | Generate a new random password |
| Forgetting to back up keys | Can make data unrecoverable | Back up and verify after each important key change |
| Skipping fingerprint verification | Can expose you to impersonation | Confirm fingerprints out of band |
| Assuming shredding defeats all storage artifacts | SSDs and journaling can preserve copies | Combine shredding with full-disk encryption |

---

## 10) Next Steps

After completing this tutorial, continue with:

- [`USER_GUIDE.md`](USER_GUIDE.md) for complete feature coverage,
- [`TECHNICAL_REFERENCE.md`](TECHNICAL_REFERENCE.md) for exact commands and parameters,
- [`../INSTALL.md`](../INSTALL.md) for installation details, and
- [`MAINTENANCE.md`](MAINTENANCE.md) for backups, upgrades, and operational care.
