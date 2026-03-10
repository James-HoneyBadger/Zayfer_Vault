"""Tests for the HB Zayfer Python bindings.

These tests exercise the native (_native) module exposed through hb_zayfer,
covering symmetric ciphers, KDF, RSA, Ed25519, X25519, OpenPGP, the HBZF
streaming format, and the on-disk keystore.

Run with:  pytest tests/python/ -v
Requires : maturin develop  (to build the native module first)
"""

from __future__ import annotations

import base64
import os
import tempfile
from pathlib import Path

import pytest

import hb_zayfer as hbz


# ===========================================================================
# Helpers
# ===========================================================================

@pytest.fixture(autouse=True)
def _isolated_keystore(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """Ensure every test gets its own keystore directory."""
    monkeypatch.setenv("HB_ZAYFER_HOME", str(tmp_path))
    # Store tmp_path on the module for KeyStore tests to use
    global _ks_path
    _ks_path = str(tmp_path)

_ks_path: str = ""


# ===========================================================================
# Version
# ===========================================================================

def test_version():
    v = hbz.version()
    assert isinstance(v, str)
    assert len(v) > 0


# ===========================================================================
# KDF
# ===========================================================================

def test_generate_salt():
    s = hbz.generate_salt(32)
    assert isinstance(s, bytes)
    assert len(s) == 32


def test_derive_key_argon2():
    salt = hbz.generate_salt(32)
    key = hbz.derive_key_argon2(b"password", salt)
    assert isinstance(key, bytes) and len(key) == 32


def test_derive_key_scrypt():
    salt = hbz.generate_salt(32)
    key = hbz.derive_key_scrypt(b"password", salt)
    assert isinstance(key, bytes) and len(key) == 32


def test_kdf_deterministic():
    salt = hbz.generate_salt(32)
    k1 = hbz.derive_key_argon2(b"hello", salt)
    k2 = hbz.derive_key_argon2(b"hello", salt)
    assert k1 == k2


def test_kdf_different_passwords():
    salt = hbz.generate_salt(32)
    k1 = hbz.derive_key_argon2(b"alpha", salt)
    k2 = hbz.derive_key_argon2(b"bravo", salt)
    assert k1 != k2


# ===========================================================================
# AES-256-GCM
# ===========================================================================

def test_aes_roundtrip():
    key = hbz.derive_key_argon2(b"pw", hbz.generate_salt(32))
    nonce, ct = hbz.aes_encrypt(key, b"Hello AES", b"")
    pt = hbz.aes_decrypt(key, nonce, ct, b"")
    assert pt == b"Hello AES"


def test_aes_wrong_key():
    k1 = hbz.derive_key_argon2(b"a", hbz.generate_salt(32))
    k2 = hbz.derive_key_argon2(b"b", hbz.generate_salt(32))
    nonce, ct = hbz.aes_encrypt(k1, b"secret", b"")
    with pytest.raises(Exception):
        hbz.aes_decrypt(k2, nonce, ct, b"")


# ===========================================================================
# ChaCha20-Poly1305
# ===========================================================================

def test_chacha_roundtrip():
    key = hbz.derive_key_argon2(b"pw", hbz.generate_salt(32))
    nonce, ct = hbz.chacha_encrypt(key, b"Hello ChaCha", b"")
    pt = hbz.chacha_decrypt(key, nonce, ct, b"")
    assert pt == b"Hello ChaCha"


def test_chacha_wrong_key():
    k1 = hbz.derive_key_argon2(b"x", hbz.generate_salt(32))
    k2 = hbz.derive_key_argon2(b"y", hbz.generate_salt(32))
    nonce, ct = hbz.chacha_encrypt(k1, b"msg", b"")
    with pytest.raises(Exception):
        hbz.chacha_decrypt(k2, nonce, ct, b"")


# ===========================================================================
# RSA
# ===========================================================================

def test_rsa_keygen():
    priv_pem, pub_pem = hbz.rsa_generate(2048)
    assert "BEGIN" in priv_pem
    assert "BEGIN" in pub_pem


def test_rsa_encrypt_decrypt():
    priv_pem, pub_pem = hbz.rsa_generate(2048)
    ct = hbz.rsa_encrypt(pub_pem, b"RSA data")
    pt = hbz.rsa_decrypt(priv_pem, ct)
    assert pt == b"RSA data"


def test_rsa_sign_verify():
    priv_pem, pub_pem = hbz.rsa_generate(2048)
    sig = hbz.rsa_sign(priv_pem, b"msg")
    assert hbz.rsa_verify(pub_pem, b"msg", sig)


def test_rsa_verify_tampered():
    priv_pem, pub_pem = hbz.rsa_generate(2048)
    sig = hbz.rsa_sign(priv_pem, b"original")
    # Tampered message should fail
    assert not hbz.rsa_verify(pub_pem, b"tampered", sig)


def test_rsa_fingerprint():
    _, pub_pem = hbz.rsa_generate(2048)
    fp = hbz.rsa_fingerprint(pub_pem)
    assert isinstance(fp, str) and len(fp) > 0
    assert hbz.rsa_fingerprint(pub_pem) == fp  # deterministic


# ===========================================================================
# Ed25519
# ===========================================================================

def test_ed25519_keygen():
    sk, vk = hbz.ed25519_generate()
    assert "BEGIN" in sk and "BEGIN" in vk


def test_ed25519_sign_verify():
    sk, vk = hbz.ed25519_generate()
    sig = hbz.ed25519_sign(sk, b"Ed25519 msg")
    assert hbz.ed25519_verify(vk, b"Ed25519 msg", sig)


def test_ed25519_verify_tampered():
    sk, vk = hbz.ed25519_generate()
    sig = hbz.ed25519_sign(sk, b"real")
    assert not hbz.ed25519_verify(vk, b"fake", sig)


def test_ed25519_fingerprint():
    _, vk = hbz.ed25519_generate()
    fp = hbz.ed25519_fingerprint(vk)
    assert isinstance(fp, str) and len(fp) > 0


# ===========================================================================
# X25519
# ===========================================================================

def test_x25519_keygen():
    sk, pk = hbz.x25519_generate()
    assert isinstance(sk, bytes) and len(sk) == 32
    assert isinstance(pk, bytes) and len(pk) == 32


def test_x25519_key_agreement():
    sk_a, pk_a = hbz.x25519_generate()
    sk_b, pk_b = hbz.x25519_generate()
    # encrypt_key_agreement(their_pub) -> (ephemeral_pub, symmetric_key)
    eph_pub, sym_key_a = hbz.x25519_encrypt_key_agreement(pk_b)
    # decrypt_key_agreement(our_secret, ephemeral_pub) -> symmetric_key
    sym_key_b = hbz.x25519_decrypt_key_agreement(sk_b, eph_pub)
    assert sym_key_a == sym_key_b
    assert len(sym_key_a) == 32


def test_x25519_fingerprint():
    _, pk = hbz.x25519_generate()
    fp = hbz.x25519_fingerprint(pk)
    assert isinstance(fp, str) and len(fp) > 0


# ===========================================================================
# OpenPGP
# ===========================================================================

def test_pgp_keygen():
    pub_arm, sec_arm = hbz.pgp_generate("Test <test@test.com>")
    assert "PGP PUBLIC KEY" in pub_arm
    assert "PGP PRIVATE KEY" in sec_arm


def test_pgp_encrypt_decrypt():
    pub_arm, sec_arm = hbz.pgp_generate("Test <t@t.com>")
    ct = hbz.pgp_encrypt(b"PGP data", [pub_arm])
    pt = hbz.pgp_decrypt(ct, sec_arm)
    assert pt == b"PGP data"


def test_pgp_sign_verify():
    pub_arm, sec_arm = hbz.pgp_generate("Signer <s@s.com>")
    signed = hbz.pgp_sign(b"signed msg", sec_arm)
    content, valid = hbz.pgp_verify(signed, pub_arm)
    assert valid
    assert content == b"signed msg"


def test_pgp_fingerprint_and_uid():
    uid = "FP Test <fp@test.com>"
    pub_arm, _ = hbz.pgp_generate(uid)
    fp = hbz.pgp_fingerprint(pub_arm)
    assert isinstance(fp, str) and len(fp) > 0
    extracted_uid = hbz.pgp_user_id(pub_arm)
    assert "FP Test" in extracted_uid


# ===========================================================================
# HBZF Streaming Format
# ===========================================================================

def test_encrypt_decrypt_data_aes():
    ct = hbz.encrypt_data(
        b"HBZF test", algorithm="aes", wrapping="password",
        passphrase=b"pw123",
    )
    assert ct[:4] == b"HBZF"
    pt = hbz.decrypt_data(ct, passphrase=b"pw123")
    assert pt == b"HBZF test"


def test_encrypt_decrypt_data_chacha():
    ct = hbz.encrypt_data(
        b"ChaCha HBZF", algorithm="chacha", wrapping="password",
        passphrase=b"cc",
    )
    pt = hbz.decrypt_data(ct, passphrase=b"cc")
    assert pt == b"ChaCha HBZF"


def test_encrypt_decrypt_data_wrong_password():
    ct = hbz.encrypt_data(
        b"secret", algorithm="aes", wrapping="password",
        passphrase=b"right",
    )
    with pytest.raises(Exception):
        hbz.decrypt_data(ct, passphrase=b"wrong")


def test_encrypt_decrypt_file(tmp_path: Path):
    src = tmp_path / "plain.txt"
    enc = tmp_path / "cipher.hbzf"
    dec = tmp_path / "decrypted.txt"

    src.write_bytes(b"file content for HBZF")
    hbz.encrypt_file(str(src), str(enc), algorithm="aes", wrapping="password",
                     passphrase=b"fp")
    assert enc.exists()

    hbz.decrypt_file(str(enc), str(dec), passphrase=b"fp")
    assert dec.read_bytes() == b"file content for HBZF"


# ===========================================================================
# KeyStore
# ===========================================================================

def test_keystore_basic():
    ks = hbz.KeyStore(_ks_path)
    keys = ks.list_keys()
    assert isinstance(keys, list)
    assert len(keys) == 0


def test_keystore_store_load_ed25519():
    ks = hbz.KeyStore(_ks_path)
    sk, vk = hbz.ed25519_generate()
    fp = hbz.ed25519_fingerprint(vk)

    ks.store_public_key(fp, vk.encode(), "ed25519", "test-key")
    ks.store_private_key(fp, sk.encode(), b"pass", "ed25519", "test-key")

    loaded_pub = ks.load_public_key(fp)
    assert loaded_pub == vk.encode()

    loaded_priv = ks.load_private_key(fp, b"pass")
    assert loaded_priv == sk.encode()


def test_keystore_wrong_passphrase():
    ks = hbz.KeyStore(_ks_path)
    sk, vk = hbz.ed25519_generate()
    fp = hbz.ed25519_fingerprint(vk)
    ks.store_private_key(fp, sk.encode(), b"correct", "ed25519", "k")
    with pytest.raises(Exception):
        ks.load_private_key(fp, b"wrong")


def test_keystore_list_and_delete():
    ks = hbz.KeyStore(_ks_path)
    sk, vk = hbz.ed25519_generate()
    fp = hbz.ed25519_fingerprint(vk)
    ks.store_public_key(fp, vk.encode(), "ed25519", "del-test")

    keys = ks.list_keys()
    assert any(k.fingerprint == fp for k in keys)

    ks.delete_key(fp)
    keys2 = ks.list_keys()
    assert not any(k.fingerprint == fp for k in keys2)


def test_keystore_contacts():
    ks = hbz.KeyStore(_ks_path)
    ks.add_contact("Alice", email="alice@example.com")

    contacts = ks.list_contacts()
    assert len(contacts) == 1
    assert contacts[0].name == "Alice"
    assert contacts[0].email == "alice@example.com"

    ks.remove_contact("Alice")
    assert len(ks.list_contacts()) == 0


def test_keystore_associate_key():
    ks = hbz.KeyStore(_ks_path)
    _, vk = hbz.ed25519_generate()
    fp = hbz.ed25519_fingerprint(vk)
    ks.store_public_key(fp, vk.encode(), "ed25519", "assoc")
    ks.add_contact("Bob")
    ks.associate_key_with_contact("Bob", fp)

    contacts = ks.list_contacts()
    assert fp in contacts[0].key_fingerprints


# ===========================================================================
# Shamir's Secret Sharing
# ===========================================================================


def test_shamir_split_combine():
    secret = b"super secret data"
    shares = hbz.shamir_split(secret, 5, 3)
    assert len(shares) == 5
    # Reconstruct with 3 of 5 shares
    recovered = hbz.shamir_combine(shares[:3])
    assert recovered == secret


def test_shamir_different_subsets():
    secret = b"another secret"
    shares = hbz.shamir_split(secret, 4, 2)
    # Any 2 shares should work
    assert hbz.shamir_combine(shares[0:2]) == secret
    assert hbz.shamir_combine(shares[2:4]) == secret
    assert hbz.shamir_combine([shares[0], shares[3]]) == secret


# ===========================================================================
# Steganography
# ===========================================================================


def test_stego_embed_extract():
    pixels = os.urandom(2000)
    payload = b"hidden message"
    modified = hbz.stego_embed(pixels, payload)
    assert len(modified) == len(pixels)
    extracted = hbz.stego_extract(modified)
    assert extracted == payload


def test_stego_capacity():
    cap = hbz.stego_capacity(8000)
    assert cap > 0
    # 8000 bytes of pixels / 8 bits per byte = 1000 bytes capacity - header
    assert cap == (8000 // 8) - 8  # minus 8 bytes for magic + length header


# ===========================================================================
# QR Key Exchange
# ===========================================================================


def test_qr_encode_decode():
    key_data = os.urandom(32)
    uri = hbz.qr_encode_key_uri("ed25519", key_data, "Test Key")
    assert uri.startswith("hbzf-key://ed25519/")
    algo, decoded_key, label = hbz.qr_decode_key_uri(uri)
    assert algo == "ed25519"
    assert decoded_key == key_data
    assert label == "Test Key"


def test_qr_encode_no_label():
    key_data = os.urandom(48)
    uri = hbz.qr_encode_key_uri("rsa-2048", key_data, None)
    algo, decoded_key, label = hbz.qr_decode_key_uri(uri)
    assert algo == "rsa-2048"
    assert decoded_key == key_data
    assert label is None


# ===========================================================================
# Password Generation
# ===========================================================================


def test_generate_password():
    pw = hbz.generate_password(length=20, uppercase=True, lowercase=True,
                                digits=True, symbols=True, exclude="")
    assert len(pw) == 20
    # Should have decent entropy
    e = hbz.password_entropy(length=20, uppercase=True, lowercase=True,
                              digits=True, symbols=True)
    assert e > 50


def test_generate_passphrase():
    pp = hbz.generate_passphrase(4, "-")
    assert "-" in pp
    words = pp.split("-")
    assert len(words) == 4
    e = hbz.passphrase_entropy(4)
    assert e > 30


def test_password_entropy_excludes():
    e_full = hbz.password_entropy(length=16, uppercase=True, lowercase=True,
                                   digits=True, symbols=True)
    # With fewer char classes, entropy should be lower
    e_less = hbz.password_entropy(length=16, uppercase=True, lowercase=True,
                                   digits=True, symbols=False)
    assert e_less < e_full


# ===========================================================================
# Utility Functions
# ===========================================================================


def test_detect_key_format():
    # ed25519 key pair is PEM
    priv, pub = hbz.ed25519_generate()
    fmt = hbz.detect_key_format(priv.encode())
    assert isinstance(fmt, str)
    assert len(fmt) > 0


def test_compute_fingerprint():
    data = b"some public key data"
    fp = hbz.compute_fingerprint(data)
    assert isinstance(fp, str)
    assert len(fp) > 0
    # Deterministic: same input → same output
    assert hbz.compute_fingerprint(data) == fp


# ===========================================================================
# Audit Logger
# ===========================================================================


def test_audit_logger_basic(tmp_path: Path):
    os.environ["HB_ZAYFER_HOME"] = str(tmp_path)
    try:
        # Log something
        hbz.audit_log_key_generated("ED25519", "abc123", "test")

        logger = hbz.AuditLogger()
        count = logger.entry_count()
        assert count >= 1

        entries = logger.recent_entries(10)
        assert len(entries) >= 1
        e = entries[0]
        assert hasattr(e, "timestamp")
        assert hasattr(e, "operation")
        assert hasattr(e, "entry_hash")

        valid = logger.verify_integrity()
        assert valid is True
    finally:
        if "HB_ZAYFER_HOME" in os.environ:
            del os.environ["HB_ZAYFER_HOME"]


def test_audit_logger_export(tmp_path: Path):
    os.environ["HB_ZAYFER_HOME"] = str(tmp_path)
    try:
        hbz.audit_log_file_encrypted("AES", "test.txt", 1024, "test")
        logger = hbz.AuditLogger()
        export_path = str(tmp_path / "audit_export.json")
        logger.export(export_path)
        assert Path(export_path).exists()
        assert Path(export_path).stat().st_size > 0
    finally:
        if "HB_ZAYFER_HOME" in os.environ:
            del os.environ["HB_ZAYFER_HOME"]


def test_audit_log_convenience_functions(tmp_path: Path):
    """All audit convenience functions should succeed without error."""
    os.environ["HB_ZAYFER_HOME"] = str(tmp_path)
    try:
        hbz.audit_log_key_generated("ED25519", "fp1", "test")
        hbz.audit_log_file_encrypted("AES", "f.txt", 100, "test")
        hbz.audit_log_file_decrypted("AES", "f.txt", 100, "test")
        hbz.audit_log_data_signed("ED25519", "fp1", "test")
        hbz.audit_log_signature_verified("ED25519", "fp1", True)
        hbz.audit_log_contact_added("Alice", "test")
        hbz.audit_log_contact_deleted("Alice", "test")
        hbz.audit_log_key_deleted("fp1", "test")

        logger = hbz.AuditLogger()
        assert logger.entry_count() >= 8
    finally:
        if "HB_ZAYFER_HOME" in os.environ:
            del os.environ["HB_ZAYFER_HOME"]


# ===========================================================================
# KeyStore Extended Methods
# ===========================================================================


def test_keystore_base_path(tmp_path: Path):
    os.environ["HB_ZAYFER_HOME"] = str(tmp_path)
    try:
        ks = hbz.KeyStore()
        bp = ks.base_path
        assert isinstance(bp, str)
        assert str(tmp_path) in bp
    finally:
        if "HB_ZAYFER_HOME" in os.environ:
            del os.environ["HB_ZAYFER_HOME"]


def test_keystore_get_key_metadata(tmp_path: Path):
    os.environ["HB_ZAYFER_HOME"] = str(tmp_path)
    try:
        ks = hbz.KeyStore()
        sk, vk = hbz.ed25519_generate()
        fp = hbz.ed25519_fingerprint(vk)
        ks.store_public_key(fp, vk.encode(), "ed25519", "meta-test")
        ks.store_private_key(fp, sk.encode(), b"pass", "ed25519", "meta-test")
        m = ks.get_key_metadata(fp)
        assert m.fingerprint == fp
        assert m.algorithm.lower() == "ed25519"
        assert m.label == "meta-test"
        assert m.has_private is True
        assert m.has_public is True
        assert len(m.created_at) > 0
    finally:
        if "HB_ZAYFER_HOME" in os.environ:
            del os.environ["HB_ZAYFER_HOME"]


def test_keystore_find_keys_by_label(tmp_path: Path):
    os.environ["HB_ZAYFER_HOME"] = str(tmp_path)
    try:
        ks = hbz.KeyStore()
        sk1, vk1 = hbz.ed25519_generate()
        sk2, vk2 = hbz.ed25519_generate()
        fp1 = hbz.ed25519_fingerprint(vk1)
        fp2 = hbz.ed25519_fingerprint(vk2)
        ks.store_public_key(fp1, vk1.encode(), "ed25519", "find-me")
        ks.store_private_key(fp1, sk1.encode(), b"p", "ed25519", "find-me")
        ks.store_public_key(fp2, vk2.encode(), "ed25519", "other")
        ks.store_private_key(fp2, sk2.encode(), b"p", "ed25519", "other")
        found = ks.find_keys_by_label("find-me")
        assert len(found) == 1
        assert found[0].label == "find-me"
    finally:
        if "HB_ZAYFER_HOME" in os.environ:
            del os.environ["HB_ZAYFER_HOME"]


def test_keystore_update_contact(tmp_path: Path):
    os.environ["HB_ZAYFER_HOME"] = str(tmp_path)
    try:
        ks = hbz.KeyStore()
        ks.add_contact("Eve", email="eve@old.com", notes="original")
        ks.update_contact("Eve", email="eve@new.com", notes="updated")
        c = ks.get_contact("Eve")
        assert c.email == "eve@new.com"
        assert c.notes == "updated"
    finally:
        if "HB_ZAYFER_HOME" in os.environ:
            del os.environ["HB_ZAYFER_HOME"]


def test_keystore_get_contact(tmp_path: Path):
    os.environ["HB_ZAYFER_HOME"] = str(tmp_path)
    try:
        ks = hbz.KeyStore()
        ks.add_contact("Dan", email="dan@test.com", notes="a note")
        c = ks.get_contact("Dan")
        assert c.name == "Dan"
        assert c.email == "dan@test.com"
        assert c.notes == "a note"
        assert len(c.created_at) > 0
    finally:
        if "HB_ZAYFER_HOME" in os.environ:
            del os.environ["HB_ZAYFER_HOME"]


def test_keystore_resolve_recipient(tmp_path: Path):
    os.environ["HB_ZAYFER_HOME"] = str(tmp_path)
    try:
        ks = hbz.KeyStore()
        sk, vk = hbz.ed25519_generate()
        fp = hbz.ed25519_fingerprint(vk)
        ks.store_public_key(fp, vk.encode(), "ed25519", "resolve-test")
        ks.store_private_key(fp, sk.encode(), b"p", "ed25519", "resolve-test")

        # Add contact and link key
        ks.add_contact("Frank")
        ks.associate_key_with_contact("Frank", fp)

        # Resolve by name should give fingerprints
        resolved = ks.resolve_recipient("Frank")
        assert fp in resolved
    finally:
        if "HB_ZAYFER_HOME" in os.environ:
            del os.environ["HB_ZAYFER_HOME"]


def test_keystore_backup_verify_restore(tmp_path: Path):
    os.environ["HB_ZAYFER_HOME"] = str(tmp_path)
    try:
        ks = hbz.KeyStore()
        sk, vk = hbz.ed25519_generate()
        fp = hbz.ed25519_fingerprint(vk)
        ks.store_public_key(fp, vk.encode(), "ed25519", "bk-test")
        ks.store_private_key(fp, sk.encode(), b"p", "ed25519", "bk-test")
        ks.add_contact("BackupBud")

        bk_path = str(tmp_path / "test_backup.hbzf")
        ks.create_backup(bk_path, b"bkpass", "py-test")

        manifest = ks.verify_backup(bk_path, b"bkpass")
        assert manifest.private_key_count >= 1
        assert manifest.contact_count >= 1
        assert manifest.label == "py-test"
        assert len(manifest.integrity_hash) > 0

        restored = ks.restore_backup(bk_path, b"bkpass")
        assert restored.private_key_count >= 1
    finally:
        if "HB_ZAYFER_HOME" in os.environ:
            del os.environ["HB_ZAYFER_HOME"]


# ===========================================================================
# Secure Shred
# ===========================================================================


def test_shred_file(tmp_path: Path):
    target = tmp_path / "shred_me.txt"
    target.write_text("sensitive data here")
    assert target.exists()
    hbz.shred_file(str(target))
    assert not target.exists()


def test_shred_directory(tmp_path: Path):
    d = tmp_path / "shred_dir"
    d.mkdir()
    (d / "a.txt").write_text("data a")
    (d / "b.txt").write_text("data b")
    hbz.shred_directory(str(d))
    assert not d.exists()