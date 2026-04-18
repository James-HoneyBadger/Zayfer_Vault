# Secure Communications Tutorial

A step-by-step guide to establishing secure communication channels using Zayfer Vault. Learn how to exchange keys safely, encrypt messages, verify identities, and maintain operational security.

---

## Table of Contents

1. [Introduction to Secure Communications](#introduction-to-secure-communications)
2. [Scenario 1: First Contact](#scenario-1-first-contact)
3. [Scenario 2: Secure File Exchange](#scenario-2-secure-file-exchange)
4. [Scenario 3: Multi-Party Communications](#scenario-3-multi-party-communications)
5. [Scenario 4: Long-Term Secure Channel](#scenario-4-long-term-secure-channel)
6. [Operational Security Guidelines](#operational-security-guidelines)
7. [Advanced: Perfect Forward Secrecy](#advanced-perfect-forward-secrecy)
8. [Common Mistakes to Avoid](#common-mistakes-to-avoid)

---

## Introduction to Secure Communications

### Security Goals

When communicating securely, you want:

1. **Confidentiality**: Only intended recipients can read messages
2. **Authenticity**: You know who sent the message
3. **Integrity**: Messages haven't been tampered with
4. **Forward Secrecy**: Past messages remain secure if keys are compromised
5. **Deniability**: Ability to deny participation (when appropriate)

### Threat Model

This tutorial addresses protection against:

- **Passive eavesdropping**: Intercepting network traffic
- **Active man-in-the-middle**: Impersonating parties
- **Compromised devices**: Stolen laptops, hacked servers
- **Social engineering**: Tricking users into revealing secrets
- **Coercion**: Being forced to reveal messages

Does NOT protect against:

- **Endpoint compromise**: Malware on your device
- **Rubber-hose cryptanalysis**: Physical coercion
- **Zero-day exploits**: Unknown vulnerabilities
- **Quantum computers**: (Use post-quantum algorithms when available)

---

## Scenario 1: First Contact

**Goal**: Establish trust with a new contact and exchange public keys securely.

### Participants

- **Alice**: Journalist who needs to receive confidential documents
- **Bob**: Whistleblower with sensitive information to share

### Step-by-Step Process

#### Phase 1: Alice Generates Keys

```bash
# Alice activates Zayfer Vault
source ~/.cargo/env  # Load Rust environment
source .venv/bin/activate  # Activate virtual environment

# Generate signing key (Ed25519 - for authentication)
hb-zayfer keygen ed25519 --label "Alice Work Signing Key 2026"
# Enter strong passphrase when prompted
# Save fingerprint: a1b2c3d4...

# Generate encryption key (X25519 - for receiving encrypted files)
hb-zayfer keygen x25519 --label "Alice Work Encryption Key 2026"
# Enter strong passphrase (different from signing key!)
# Save fingerprint: e5f6g7h8...

# Export public keys
hb-zayfer keys export a1b2c3d4 -o alice-signing-2026.pub
hb-zayfer keys export e5f6g7h8 -o alice-encryption-2026.pub
```

**What Alice now has:**
- Two key pairs (signing + encryption)
- Two public key files to share
- Private keys secured with passphrases in keystore

#### Phase 2: Bob Generates Keys

```bash
# Bob does the same
source .venv/bin/activate

hb-zayfer keygen ed25519 --label "Bob Anonymous Signing Key"
# Fingerprint: b8c9d0e1...

hb-zayfer keygen x25519 --label "Bob Anonymous Encryption Key"
# Fingerprint: f2g3h4i5...

hb-zayfer keys export b8c9d0e1 -o bob-signing.pub
hb-zayfer keys export f2g3h4i5 -o bob-encryption.pub
```

#### Phase 3: Secure Key Exchange

**Critical Step**: Keys must be exchanged over a channel different from where you'll communicate.

**Good methods** (in order of security):

1. **In-person meeting**: Physically meet and exchange via USB drive
   - Safest: No network exposure
   - Verify fingerprints verbally

2. **Secure courier**: Use trusted third party
   - Use sealed tamper-evident envelope
   - Include fingerprints on separate paper

3. **Separate secure channels**: 
   - Post public keys on personal website (HTTPS)
   - Share fingerprints via phone call or Signal
   - Cross-verify using both channels

4. **Keyserver with fingerprint verification**:
   - Upload to PGP keyserver
   - Share fingerprint via Tweet, LinkedIn, business card
   - Recipient verifies fingerprint matches

**Alice shares her public keys:**

```bash
# Option A: Upload to personal website
scp alice-*.pub alice@example.com:/var/www/html/keys/

# Option B: Send via secure email (encrypted with existing PGP)
gpg --encrypt --recipient old-contact@example.com alice-signing-2026.pub

# Option C: Post fingerprint publicly
echo "My Zayfer Vault key fingerprints:"
echo "Signing: a1b2c3d4e5f6789012345678901234567890abcdef"
echo "Encryption: e5f6g7h8i9j0123456789012345678901234567890abc"
```

**Bob retrieves Alice's keys:**

```bash
# Download from Alice's website
curl https://alice.example.com/keys/alice-signing-2026.pub -o alice-signing.pub
curl https://alice.example.com/keys/alice-encryption-2026.pub -o alice-encryption.pub

# CRITICAL: Verify fingerprints via separate channel
hb-zayfer keys import alice-signing.pub --label "Alice Work Signing" --algorithm ed25519
# Displayed fingerprint: a1b2c3d4e5f6789012345678901234567890abcdef

# Bob calls Alice on the phone:
# Bob: "Is your signing key fingerprint alpha-one-bravo-two-charlie-three...?"
# Alice: "Yes, that's correct."
# [If fingerprints don't match: DO NOT PROCEED - possible MITM attack]

hb-zayfer keys import alice-encryption.pub --label "Alice Work Encryption" --algorithm x25519
```

**Alice imports Bob's keys** (same verification process)

#### Phase 4: Add to Contacts

```bash
# Alice adds Bob as contact
hb-zayfer contacts add "Bob (Whistleblower)" --email bob.anonymous@protonmail.com

# Link Bob's keys to contact
hb-zayfer contacts link "Bob (Whistleblower)" b8c9d0e1
hb-zayfer contacts link "Bob (Whistleblower)" f2g3h4i5

# Bob adds Alice as contact
hb-zayfer contacts add "Alice (Journalist)" --email alice@example.com
hb-zayfer contacts link "Alice (Journalist)" a1b2c3d4
hb-zayfer contacts link "Alice (Journalist)" e5f6g7h8
```

#### Phase 5: Test Communication

**Bob sends test message to Alice:**

```bash
# Create test message
echo "This is a test of our secure channel. -Bob" > test-message.txt

# Encrypt for Alice
hb-zayfer encrypt test-message.txt -o test-message.hbzf --recipient "Alice (Journalist)"

# Sign the encrypted file (proves it's from Bob)
hb-zayfer sign test-message.hbzf -o test-message.hbzf.sig --key b8c9d0e1

# Send both files to Alice (via any channel - they're encrypted)
# Email, file sharing, USB drop, etc.
```

**Alice receives and verifies:**

```bash
# First verify signature (proves it's from Bob, not tampered with)
hb-zayfer verify test-message.hbzf test-message.hbzf.sig --key b8c9d0e1

# Output: "✓ Signature is VALID"
# If invalid: DO NOT DECRYPT - message may be compromised

# Decrypt the message
hb-zayfer decrypt test-message.hbzf -o test-message.txt
# Enter passphrase for Alice's encryption key

# Read message
cat test-message.txt
```

**Success!** Alice and Bob now have:
- Verified each other's identities
- Exchanged and verified public keys
- Tested encryption and signing
- Established contact entries for easy reference

---

## Scenario 2: Secure File Exchange

**Goal**: Bob needs to send Alice a 500MB document archive with absolute security.

### Step-by-Step Process

#### Bob Prepares the Archive

```bash
# Create compressed archive of documents
tar czf sensitive-docs.tar.gz documents/

# Verify archive integrity
sha256sum sensitive-docs.tar.gz > checksums.txt
cat checksums.txt
# Save this hash separately for Alice to verify

# Encrypt for Alice (uses her X25519 public key)
hb-zayfer encrypt sensitive-docs.tar.gz -o sensitive-docs.hbzf --recipient "Alice (Journalist)" --algorithm aes

# Sign the encrypted archive
hb-zayfer sign sensitive-docs.hbzf -o sensitive-docs.hbzf.sig --key b8c9d0e1  # Bob's signing key

# Create manifest file
cat > MANIFEST.txt << EOF
File: sensitive-docs.hbzf
Original SHA256: $(cat checksums.txt)
Encrypted Size: $(stat -f%z sensitive-docs.hbzf) bytes
Encrypted SHA256: $(sha256sum sensitive-docs.hbzf)
Signature: sensitive-docs.hbzf.sig
Sender: Bob (key b8c9d0e1)
Recipient: Alice (key e5f6g7h8)
Date: $(date -u +"%Y-%m-%d %H:%M:%S UTC")
EOF

# Sign the manifest too
hb-zayfer sign MANIFEST.txt -o MANIFEST.txt.sig --key b8c9d0e1
```

#### Bob Transfers Files Securely

**Option 1: Upload to secure file sharing**

```bash
# Upload to encrypted file hosting (Tresorit, ProtonDrive, Sync.com)
# Share link with Alice via separate channel (Signal, encrypted email)

# Security note: File sharing services can see encrypted file,
# but cannot decrypt without Alice's private key
```

**Option 2: Split and distribute**

```bash
# Split large file into chunks
split -b 100M sensitive-docs.hbzf sensitive-docs.hbzf.part-

# Upload parts to different services
# Send reconstitution instructions to Alice separately
```

**Option 3: Physical transfer**

```bash
# Write to encrypted USB drive
# Mail via secure courier
# Hand-deliver at secret meeting location
```

#### Bob Notifies Alice

**Send via secure channel (Signal, encrypted email):**

```
Subject: Archive Ready

Alice,

I have uploaded the document archive. Details:

Encrypted File: sensitive-docs.hbzf (2.1 GB)
Signature: sensitive-docs.hbzf.sig
Manifest: MANIFEST.txt + .sig

Encrypted file SHA256: [hash from MANIFEST.txt]

Download link: [secure file sharing link]
Password for link: [separate password, shared via phone]

Please verify:
1. File SHA256 matches manifest
2. Manifest signature validates
3. Archive signature validates
4. Decryption succeeds

Shred all files after extraction. Call me when received.

-B
```

#### Alice Receives and Verifies

```bash
# Download files
curl -O "https://securefileserver.com/download/sensitive-docs.hbzf"
curl -O "https://securefilesharing.com/download/sensitive-docs.hbzf.sig"
curl -O "https://securefilesharing.com/download/MANIFEST.txt"
curl -O "https://securefilesharing.com/download/MANIFEST.txt.sig"

# Step 1: Verify manifest signature
hb-zayfer verify MANIFEST.txt MANIFEST.txt.sig --key b8c9d0e1  # Bob's signing key

# Output: "✓ Signature is VALID"

# Step 2: Verify encrypted file hash matches manifest
sha256sum sensitive-docs.hbzf
# Compare with hash in MANIFEST.txt
# If different: STOP - file corrupted or tampered

# Step 3: Verify archive signature
hb-zayfer verify sensitive-docs.hbzf sensitive-docs.hbzf.sig --key b8c9d0e1

# Output: "✓ Signature is VALID"

# Step 4: Decrypt
hb-zayfer decrypt sensitive-docs.hbzf -o sensitive-docs.tar.gz
# Enter passphrase for Alice's encryption key

# Step 5: Verify decrypted file hash
sha256sum sensitive-docs.tar.gz
# Compare with "Original SHA256" from MANIFEST.txt

# Step 6: Extract
tar xzf sensitive-docs.tar.gz

# Step 7: Secure cleanup (using Zayfer Vault's built-in shredder)
hb-zayfer shred sensitive-docs.hbzf --passes 7
hb-zayfer shred sensitive-docs.tar.gz --passes 7
# Keep only extracted documents
```

#### Alice Confirms Receipt

```bash
# Generate receipt signature
echo "Received sensitive-docs archive on $(date -u +"%Y-%m-%d %H:%M:%S UTC"). All verification passed. -Alice" > receipt.txt

# Sign receipt
hb-zayfer sign receipt.txt -o receipt.sig --key a1b2c3d4

# Send receipt.txt and receipt.sig back to Bob
# Bob verifies Alice's signature to confirm she received it
```

---

## Scenario 3: Multi-Party Communications

**Goal**: Alice, Bob, and Charlie need to share information securely.

### Establishing the Group

#### Each Member Generates Keys

```bash
# Alice (already has keys from Scenario 1)
# Bob (already has keys from Scenario 1)

# Charlie generates keys
hb-zayfer keygen ed25519 --label "Charlie Signing Key"  # c1d2e3f4
hb-zayfer keygen x25519 --label "Charlie Encryption Key"  # g5h6i7j8
```

#### Full Key Exchange

**Everyone exports and shares their public keys** (using methods from Scenario 1).

Each person imports the others' keys:

```bash
# Alice imports Bob and Charlie
hb-zayfer keys import bob-signing.pub --label "Bob Sign" --algorithm ed25519
hb-zayfer keys import bob-encryption.pub --label "Bob Encrypt" --algorithm x25519
hb-zayfer keys import charlie-signing.pub --label "Charlie Sign" --algorithm ed25519
hb-zayfer keys import charlie-encryption.pub --label "Charlie Encrypt" --algorithm x25519

# Alice adds contacts
hb-zayfer contacts add "Bob" --email bob@example.com
hb-zayfer contacts link "Bob" b8c9d0e1
hb-zayfer contacts link "Bob" f2g3h4i5

hb-zayfer contacts add "Charlie" --email charlie@example.com
hb-zayfer contacts link "Charlie" c1d2e3f4
hb-zayfer contacts link "Charlie" g5h6i7j8
```

**Bob and Charlie do the same** to import all members' keys.

### Multi-Recipient Encryption

**Alice broadcasts a message to Bob and Charlie:**

```bash
# Create message
echo "Team meeting at safe house. Details: [coordinates]. -A" > meeting-notice.txt

# Encrypt for Bob
hb-zayfer encrypt meeting-notice.txt -o meeting-notice-for-bob.hbzf --recipient "Bob"

# Encrypt for Charlie
hb-zayfer encrypt meeting-notice.txt -o meeting-notice-for-charlie.hbzf --recipient "Charlie"

# Sign both (proves they're from Alice)
hb-zayfer sign meeting-notice-for-bob.hbzf -o bob.sig --key a1b2c3d4
hb-zayfer sign meeting-notice-for-charlie.hbzf -o charlie.sig --key a1b2c3d4

# Send to each recipient
# Bob receives: meeting-notice-for-bob.hbzf + bob.sig
# Charlie receives: meeting-notice-for-charlie.hbzf + charlie.sig

# Securely delete plaintext
hb-zayfer shred meeting-notice.txt
```

### Shared Secret Method (Alternative)

Instead of encrypting separately for each recipient, use a shared group password:

```bash
# Step 1: Generate strong random password using Zayfer Vault
hb-zayfer passgen --length 32
# Or generate a memorable passphrase
hb-zayfer passgen --passphrase --words 8
# Example: correct-horse-battery-staple-gamma-river-cloud-nine

# Step 2: Share password with all members in person or via secure voice call
# Each member saves password securely (password manager, encrypted note)

# Step 3: Alice encrypts for group
hb-zayfer encrypt meeting-notice.txt -o meeting-notice-group.hbzf -p --algorithm aes
# Enter group password when prompted

# Step 4: Alice signs
hb-zayfer sign meeting-notice-group.hbzf -o meeting.sig --key a1b2c3d4

# Step 5: Distribute to all members
# All members use same password to decrypt
```

**Group password security:**
- Change password monthly
- Use strong random passwords (30+ characters)
- Never send password over same channel as encrypted files
- Revoke immediately if member leaves group or is compromised

---

## Scenario 4: Long-Term Secure Channel

**Goal**: Alice and Bob need ongoing secure communications for months/years.

### Key Rotation Strategy

**Problem**: Using same keys forever increases risk. If key is compromised, ALL past messages are readable.

**Solution**: Rotate keys periodically.

#### Initial Setup (Month 1)

```bash
# Alice generates 2026 keys
hb-zayfer keygen ed25519 --label "Alice 2026-Q1 Signing"
hb-zayfer keygen x25519 --label "Alice 2026-Q1 Encryption"

# Bob generates 2026 keys
hb-zayfer keygen ed25519 --label "Bob 2026-Q1 Signing"
hb-zayfer keygen x25519 --label "Bob 2026-Q1 Encryption"

# Exchange keys (as in Scenario 1)
```

#### Quarterly Rotation (Month 4)

```bash
# Alice generates new keys
hb-zayfer keygen ed25519 --label "Alice 2026-Q2 Signing"
hb-zayfer keygen x25519 --label "Alice 2026-Q2 Encryption"

# Export and share new public keys with Bob
hb-zayfer keys export <new-signing-fingerprint> -o alice-2026-q2-signing.pub
hb-zayfer keys export <new-encryption-fingerprint> -o alice-2026-q2-encryption.pub

# Send to Bob with signed transition message:
cat > key-rotation-notice.txt << EOF
Bob,

I am rotating my keys for Q2 2026.

New signing key: <fingerprint>
New encryption key: <fingerprint>

Old keys valid until: 2026-04-30
After that date, use only new keys.

Attached: alice-2026-q2-signing.pub, alice-2026-q2-encryption.pub

-Alice
EOF

# Sign with OLD key (proves continuity)
hb-zayfer sign key-rotation-notice.txt -o rotation.sig --key <old-signing-key>

# Send to Bob
```

**Bob verifies transition:**

```bash
# Verify signature with Alice's OLD key
hb-zayfer verify key-rotation-notice.txt rotation.sig --key <alice-old-signing-fingerprint>

# Import new keys
hb-zayfer keys import alice-2026-q2-signing.pub --label "Alice 2026-Q2 Sign" --algorithm ed25519
hb-zayfer keys import alice-2026-q2-encryption.pub --label "Alice 2026-Q2 Encrypt" --algorithm x25519

# Verify new key fingerprints via phone call

# Update contact
hb-zayfer contacts link "Alice" <new-signing-fingerprint>
hb-zayfer contacts link "Alice" <new-encryption-fingerprint>
```

**After transition period:**

```bash
# Alice deletes old private keys (after 30-day overlap period)
hb-zayfer keys delete <old-signing-fingerprint>
hb-zayfer keys delete <old-encryption-fingerprint>

# Keep old public keys for signature verification of old messages
```

### Forward Secrecy Best Practices

To achieve forward secrecy (past messages stay secure if current key is compromised):

1. **Rotate encryption keys quarterly**
2. **Delete old private keys after rotation**
3. **Keep old public keys for verifying historical signatures**
4. **Use session-based encryption for chat** (Signal Protocol if real-time)
5. **Destroy plaintext after reading**

```bash
# Secure file destruction after reading (Zayfer Vault built-in shredder)
hb-zayfer shred decrypted-message.txt --passes 7

# Encrypted file can be kept (can't be decrypted after key deletion)
```

---

## Operational Security Guidelines

### Communication Hygiene

✅ **DO:**

1. **Verify fingerprints** out-of-band for every new contact
2. **Sign all encrypted files** to prove authenticity
3. **Verify signatures** before decrypting
4. **Use unique passphrases** for each key
5. **Destroy plaintext** after encryption
6. **Rotate keys** quarterly or annually
7. **Separate channels** for key exchange and encrypted comms
8. **Test** encryption/decryption before critical use
9. **Back up keystores** with different passphrase
10. **Monitor audit logs** for unauthorized operations

❌ **DON'T:**

1. **Don't reuse keys** across contexts
2. **Don't send public keys and encrypted files** in same message
3. **Don't use weak passphrases** (< 12 characters)
4. **Don't skip signature verification** ("just this once")
5. **Don't keep plaintext and ciphertext** in same location
6. **Don't share private keys** under any circumstances
7. **Don't use compromised devices** for encryption
8. **Don't trust key exchanges** over insecure channels
9. **Don't forget to destroy** failed/test encryptions
10. **Don't panic** if you suspect compromise - follow incident plan

### Metadata Protection

**Remember**: Encryption hides content but not metadata.

**Exposed metadata:**
- File sizes
- Timestamps
- Sender/recipient identities (if not using anonymization)
- Number of messages
- Communication patterns

**Mitigation strategies:**

```bash
# Add random padding to hide true file size
dd if=/dev/urandom bs=1M count=$((RANDOM % 10 + 1)) >> padding.bin
cat document.txt padding.bin > document-padded.txt
hb-zayfer encrypt document-padded.txt ...

# Use Tor for file transfers
torsocks curl -T encrypted.hbzf https://filehost.onion/upload

# Delay sending to break timing correlation
sleep $((RANDOM % 3600))  # Random delay 0-60 minutes
upload-file encrypted.hbzf

# Use dead drops instead of direct messaging
# Upload to anonymous location, share location separately
```

### Device Security

**Endpoint security is critical** - encryption can't protect against:

1. **Keyloggers**: Capture passphrases as you type
2. **Screen capture**: Record plaintext after decryption
3. **Memory dumps**: Extract keys from RAM
4. **Malware**: Backdoor encryption software

**Mitigation:**

```bash
# Use dedicated hardware for sensitive operations
# - Air-gapped laptop for decryption
# - Hardware security key for passphrase storage

# Encrypted boot
# - Full disk encryption (LUKS, FileVault, BitLocker)
# - Secure boot enabled

# Minimal attack surface
# - Dedicated OS installation (Tails, Qubes OS)
# - No unnecessary software
# - No network during decryption (airplane mode)

# Secure erasure
# - shred instead of rm
# - Overwrite RAM on shutdown
# - Physical destruction for highly sensitive keys
```

### Incident Response Plan

**If you suspect key compromise:**

1. **Assume compromise** until proven otherwise
2. **Stop using** compromised key immediately
3. **Generate new keys** on clean system
4. **Notify contacts** of compromise
5. **Revoke old keys** (if using PGP keyserver)
6. **Investigate** how compromise occurred
7. **Review audit logs** for unauthorized operations
8. **Forensics**: Preserve evidence if criminal activity

**Example incident notification:**

```
Subject: URGENT: Key Compromise Notification

My Zayfer Vault signing key (fingerprint: a1b2c3d4...) may be compromised.

DO NOT:
- Trust messages signed with this key after 2026-03-08
- Send me encrypted files using old encryption key

NEW KEYS:
- Signing: x9y8z7w6... (verify this via phone call)
- Encryption: v5u4t3s2...

Public keys attached. Please verify fingerprints by calling me.

-Alice
```

---

## Advanced: Perfect Forward Secrecy

### Understanding Forward Secrecy

**Problem**: If your long-term encryption key is compromised, attacker can decrypt ALL past messages.

**Solution**: Use ephemeral keys that are destroyed after each session.

### Implementing Forward Secrecy

#### Per-Session Keys

```bash
# For each message session, generate temporary key
hb-zayfer keygen x25519 --label "Session 2026-03-08-14:30"

# Use for this conversation only
hb-zayfer encrypt message.txt -o message.hbzf --recipient "Bob"

# After Bob confirms receipt, delete the private key
hb-zayfer keys delete <session-key-fingerprint>

# Next session: generate new ephemeral key
```

#### Signal-style Ratcheting (Manual)

```bash
# Alice and Bob establish shared secret (in person or via ECDH)
SHARED_SECRET="k9mL2p5rT8vY1wQ3nF6xZ0aH4jS7dG9b"

# Message 1: Derive key from shared secret
echo "$SHARED_SECRET:message1" | sha256sum > key1.txt
# Encrypt with derived key, send to Bob

# Message 2: Derive next key from previous key
cat key1.txt | sha256sum > key2.txt
# Encrypt with key2, send to Bob

# Destroy previous key
hb-zayfer shred key1.txt

# Each message uses new derived key
# Compromise of current key doesn't expose past messages
```

### Trade-offs

**Pros:**
- Past messages secure even if current key compromised
- No long-term key to protect
- Resistance to future quantum computers

**Cons:**
- Can't decrypt old messages (by design)
- More complex key management
- Need synchronization between parties
- Not suitable for asynchronous communication

**When to use:**
- Real-time chat or voice
- Highly sensitive communications
- Adversary with powerful resources
- Long-term security requirements

**When not to use:**
- Email or asynchronous messaging
- Need to retain message history
- Low-threat environment

---

## Common Mistakes to Avoid

### Mistake 1: Trusting Unverified Keys

❌ **Bad:**
```bash
# Download key from website, use immediately
curl https://bob.com/pubkey.pem | hb-zayfer keys import --label "Bob" --algorithm ed25519
hb-zayfer encrypt secret.txt --recipient "Bob"
```

✅ **Good:**
```bash
# Download key
curl https://bob.com/pubkey.pem -o bob.pem

# Import
hb-zayfer keys import bob.pem --label "Bob" --algorithm ed25519

# Verify fingerprint out-of-band
hb-zayfer keys info <bob-fingerprint>
# Call Bob, verify fingerprint matches

# Only then: encrypt
hb-zayfer encrypt secret.txt --recipient "Bob"
```

### Mistake 2: Skipping Signatures

❌ **Bad:**
```bash
# Just encrypt and send
hb-zayfer encrypt doc.txt -o doc.hbzf --recipient "Alice"
# Alice has no proof this is really from you
```

✅ **Good:**
```bash
# Encrypt AND sign
hb-zayfer encrypt doc.txt -o doc.hbzf --recipient "Alice"
hb-zayfer sign doc.hbzf -o doc.hbzf.sig --key <my-signing-key>
# Alice can verify it's really from you
```

### Mistake 3: Weak Passphrases

❌ **Bad:**
```
Passphrase: password123
Passphrase: myname1985
Passphrase: qwerty
```

✅ **Good:**
```
Passphrase: correct-horse-battery-staple-7391-gamma
Passphrase: TzL9#mK2@pR5$vN8^wQ3!xF6
Passphrase: [use password manager to generate 20+ character random]
```

### Mistake 4: Keeping Plaintext After Encryption

❌ **Bad:**
```bash
hb-zayfer encrypt secret.txt -o secret.hbzf
# secret.txt still on disk - can be recovered even after deletion
```

✅ **Good:**
```bash
hb-zayfer encrypt secret.txt -o secret.hbzf
hb-zayfer shred secret.txt
# Plaintext securely destroyed (3-pass overwrite + unlink)
```

### Mistake 5: Using Same Key Everywhere

❌ **Bad:**
```bash
# One key for work, personal, side projects, testing, etc.
hb-zayfer keygen ed25519 --label "My Only Key"
```

✅ **Good:**
```bash
# Separate keys for separate contexts
hb-zayfer keygen ed25519 --label "Work Signing 2026"
hb-zayfer keygen ed25519 --label "Personal Signing 2026"
hb-zayfer keygen ed25519 --label "Open Source Projects 2026"
```

### Mistake 6: No Backups (or Unencrypted Backups)

❌ **Bad:**
```bash
# No backup
# OR
cp -r ~/.hb_zayfer/ ~/backup/
# Unencrypted copy of all your keys!
```

✅ **Good:**
```bash
# Create encrypted backup
hb-zayfer backup create -o ~/backups/keystore-$(date +%Y%m%d).hbzf
# Stored encrypted with separate passphrase
```

### Mistake 7: Poor OPSEC

❌ **Bad:**
```bash
# Email plaintext then encrypted file together
mail -s "Here's the secret" alice@example.com < secret.txt
mail -s "Also encrypted version" alice@example.com < secret.hbzf
```

✅ **Good:**
```bash
# Encrypt first, destroy plaintext, send only encrypted
hb-zayfer encrypt secret.txt -o secret.hbzf
hb-zayfer shred secret.txt
# Send secret.hbzf via email/file sharing
# Share decryption key via separate channel (phone, in-person)
```

---

## Checklist: Secure Communication Setup

Use this checklist when establishing new secure channel:

- [ ] Generated signing key (Ed25519)
- [ ] Generated encryption key (X25519 or RSA-4096)
- [ ] Used strong, unique passphrases for each key
- [ ] Backed up keystore with separate passphrase
- [ ] Exported public keys
- [ ] Shared public keys via secure method
- [ ] Verified recipient's key fingerprints out-of-band
- [ ] Imported recipient's public keys
- [ ] Verified imported key fingerprints
- [ ] Added recipient to contacts
- [ ] Linked keys to contact
- [ ] Sent test message (encrypted + signed)
- [ ] Verified test message signature
- [ ] Decrypted test message successfully
- [ ] Established key rotation schedule
- [ ] Documented emergency contact procedures
- [ ] Created incident response plan
- [ ] Tested backup restoration
- [ ] Configured audit logging
- [ ] Secured device (full disk encryption, etc.)

---

## Using Shamir's Secret Sharing for Group Keys

Instead of trusting one person with a group passphrase, split it among members:

```bash
# Generate a strong group passphrase
GROUP_SECRET=$(hb-zayfer passgen --length 32)

# Split into 5 shares, need 3 to reconstruct (3-of-5 quorum)
hb-zayfer shamir split --secret "$GROUP_SECRET" -n 5 -k 3
# Outputs 5 hex-encoded shares

# Distribute one share to each custodian (Alice, Bob, Charlie, Dave, Eve)
# Any 3 can reconstruct the secret:
hb-zayfer shamir combine --shares "share1,share2,share3"
```

**Use cases:**
- Corporate key escrow (3-of-5 executives)
- Dead-man's switch (shares held by lawyers, family, colleagues)
- Multi-party authorization for high-value decryption

## QR Key Exchange for In-Person Meetings

When meeting in person, use QR codes for fast, error-free key exchange:

```bash
# Generate a QR-friendly key URI
python -c "
import hb_zayfer as hbz
uri = hbz.qr_encode_key_uri('ed25519', 'a1b2c3d4...', 'Alice')
print(uri)  # hbzf-key://ed25519/a1b2c3d4...?label=Alice
"

# In the GUI: open 📱 QR Exchange view
# - Enter algorithm + fingerprint → generates QR code
# - Other party scans with their phone/camera
# - Automatically imports key URI
```

**Advantages over manual fingerprint comparison:**
- No transcription errors
- Faster (scan vs. read 64 hex characters aloud)
- Works across devices (laptop → phone, phone → phone)

---

## Next Steps

After completing this tutorial:

1. **Practice**: Set up test communications with a trusted friend
2. **Document**: Write your own operational procedures
3. **Train**: Teach others in your organization
4. **Audit**: Review logs regularly for anomalies
5. **Update**: Stay current on cryptographic best practices
6. **Plan**: Prepare for key compromise scenarios

## Additional Resources

- [USER_GUIDE.md](USER_GUIDE.md) - Complete feature reference
- [SECURITY.md](SECURITY.md) - Threat model and security architecture
- [CLI.md](CLI.md) - Command-line reference
- [PYTHON_API.md](PYTHON_API.md) - API documentation for automation

---

**Remember**: Security is a process, not a product. Stay vigilant, keep learning, and never stop questioning your assumptions.

