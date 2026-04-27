"""Zayfer Vault — Full-featured encryption/decryption suite.

This package exposes the Rust-powered cryptographic core via a clean
Python API. All heavy cryptographic operations run in native Rust with
the GIL released.

Quick start::

    import hb_zayfer as hbz

    # Password-based file encryption
    hbz.encrypt_file("secret.pdf", "secret.pdf.hbzf", passphrase=b"hunter2")
    hbz.decrypt_file("secret.pdf.hbzf", "recovered.pdf", passphrase=b"hunter2")

    # RSA key generation & encrypt/decrypt
    priv_pem, pub_pem = hbz.rsa_generate(4096)
    ct = hbz.rsa_encrypt(pub_pem, b"hello")
    assert hbz.rsa_decrypt(priv_pem, ct) == b"hello"

    # Key store & contacts
    ks = hbz.KeyStore()
    ks.add_contact("Alice", email="alice@example.com")
"""

from __future__ import annotations

from hb_zayfer._native import (
    AuditEntry,
    AuditLogger,
    AuthenticationError,
    BackupManifest,
    Contact,
    ContactAlreadyExistsError,
    ContactNotFoundError,
    IntegrityError,
    KeyAlreadyExistsError,
    KeyMetadata,
    KeyNotFoundError,
    # Classes
    KeyStore,
    # Typed exceptions
    ZayferError,
    aes_decrypt,
    # Symmetric – AES-256-GCM
    aes_encrypt,
    audit_log_contact_added,
    audit_log_contact_deleted,
    audit_log_data_signed,
    audit_log_file_decrypted,
    audit_log_file_encrypted,
    audit_log_key_deleted,
    audit_log_key_generated,
    audit_log_signature_verified,
    chacha_decrypt,
    # Symmetric – ChaCha20-Poly1305
    chacha_encrypt,
    # Utilities
    compute_fingerprint,
    decrypt_data,
    decrypt_file,
    derive_key_argon2,
    derive_key_scrypt,
    detect_key_format,
    ed25519_fingerprint,
    # Ed25519
    ed25519_generate,
    ed25519_sign,
    ed25519_verify,
    # HBZF format
    encrypt_data,
    encrypt_file,
    generate_passphrase,
    # Password generation
    generate_password,
    # KDF
    generate_salt,
    passphrase_entropy,
    password_entropy,
    pgp_decrypt,
    pgp_encrypt,
    pgp_fingerprint,
    # OpenPGP
    pgp_generate,
    pgp_sign,
    pgp_user_id,
    pgp_verify,
    qr_decode_key_uri,
    # QR key exchange
    qr_encode_key_uri,
    rsa_decrypt,
    rsa_encrypt,
    rsa_fingerprint,
    # RSA
    rsa_generate,
    rsa_sign,
    rsa_verify,
    shamir_combine,
    # Shamir's Secret Sharing
    shamir_split,
    shred_directory,
    # Secure shredding
    shred_file,
    stego_capacity,
    # Steganography
    stego_embed,
    stego_extract,
    # Version
    version,
    x25519_decrypt_key_agreement,
    x25519_encrypt_key_agreement,
    x25519_fingerprint,
    # X25519
    x25519_generate,
)
from hb_zayfer.services import (
    AppInfo,
    AppPaths,
    AuditService,
    BackupService,
    ConfigService,
    CryptoService,
    KeyService,
    SignatureService,
    WorkspaceSummary,
)

__all__ = [
    "version",
    # Symmetric
    "aes_encrypt",
    "aes_decrypt",
    "chacha_encrypt",
    "chacha_decrypt",
    # KDF
    "generate_salt",
    "derive_key_argon2",
    "derive_key_scrypt",
    # RSA
    "rsa_generate",
    "rsa_encrypt",
    "rsa_decrypt",
    "rsa_sign",
    "rsa_verify",
    "rsa_fingerprint",
    # Ed25519
    "ed25519_generate",
    "ed25519_sign",
    "ed25519_verify",
    "ed25519_fingerprint",
    # X25519
    "x25519_generate",
    "x25519_encrypt_key_agreement",
    "x25519_decrypt_key_agreement",
    "x25519_fingerprint",
    # OpenPGP
    "pgp_generate",
    "pgp_encrypt",
    "pgp_decrypt",
    "pgp_sign",
    "pgp_verify",
    "pgp_fingerprint",
    "pgp_user_id",
    # HBZF format
    "encrypt_data",
    "decrypt_data",
    "encrypt_file",
    "decrypt_file",
    # Utilities
    "compute_fingerprint",
    "detect_key_format",
    "audit_log_key_generated",
    "audit_log_file_encrypted",
    "audit_log_file_decrypted",
    "audit_log_data_signed",
    "audit_log_signature_verified",
    "audit_log_contact_added",
    "audit_log_contact_deleted",
    "audit_log_key_deleted",
    # Password generation
    "generate_password",
    "generate_passphrase",
    "password_entropy",
    "passphrase_entropy",
    # Shamir's Secret Sharing
    "shamir_split",
    "shamir_combine",
    # Steganography
    "stego_embed",
    "stego_extract",
    "stego_capacity",
    # Secure shredding
    "shred_file",
    "shred_directory",
    # QR key exchange
    "qr_encode_key_uri",
    "qr_decode_key_uri",
    # Classes
    "KeyStore",
    "KeyMetadata",
    "Contact",
    "BackupManifest",
    "AuditEntry",
    "AuditLogger",
    # Typed exceptions
    "ZayferError",
    "AuthenticationError",
    "KeyNotFoundError",
    "ContactNotFoundError",
    "IntegrityError",
    "KeyAlreadyExistsError",
    "ContactAlreadyExistsError",
    # Version
    "__version__",
    # Shared services
    "AppInfo",
    "AppPaths",
    "AuditService",
    "BackupService",
    "ConfigService",
    "CryptoService",
    "KeyService",
    "SignatureService",
    "WorkspaceSummary",
]

__version__ = version()
