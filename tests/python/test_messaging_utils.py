"""Regression tests for the secure messaging helpers used by the GUI."""

from __future__ import annotations

import json
from pathlib import Path

import hb_zayfer as hbz
import pytest

pytest.importorskip("PySide6")

from hb_zayfer.gui.messaging_utils import create_message_package, decrypt_message_package


@pytest.fixture(autouse=True)
def _isolated_keystore(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("HB_ZAYFER_HOME", str(tmp_path))


def _store_rsa_key(label: str, passphrase: bytes) -> str:
    ks = hbz.KeyStore()
    priv_pem, pub_pem = hbz.rsa_generate(2048)
    fp = hbz.rsa_fingerprint(pub_pem)
    ks.store_private_key(fp, priv_pem.encode(), passphrase, "rsa2048", label)
    ks.store_public_key(fp, pub_pem.encode(), "rsa2048", label)
    return fp


def _store_ed25519_key(label: str, passphrase: bytes) -> str:
    ks = hbz.KeyStore()
    sk_pem, vk_pem = hbz.ed25519_generate()
    fp = hbz.ed25519_fingerprint(vk_pem)
    ks.store_private_key(fp, sk_pem.encode(), passphrase, "ed25519", label)
    ks.store_public_key(fp, vk_pem.encode(), "ed25519", label)
    return fp


def _store_x25519_key(label: str, passphrase: bytes) -> str:
    ks = hbz.KeyStore()
    sk_raw, pk_raw = hbz.x25519_generate()
    fp = hbz.x25519_fingerprint(pk_raw)
    ks.store_private_key(fp, sk_raw, passphrase, "x25519", label)
    ks.store_public_key(fp, pk_raw, "x25519", label)
    return fp


def test_create_and_decrypt_message_package_with_signature():
    sender_fp = _store_ed25519_key("sender", b"sender-pass")
    recipient_fp = _store_rsa_key("recipient", b"recipient-pass")

    package_text = create_message_package(
        "hello secure world",
        recipient_fingerprint=recipient_fp,
        sender_fingerprint=sender_fp,
        sender_passphrase="sender-pass",
    )

    package = json.loads(package_text)
    assert package["format"] == "hbz-message"
    assert package["recipient_fingerprint"] == recipient_fp
    assert package["sender_fingerprint"] == sender_fp
    assert package["signature_b64"]

    result = decrypt_message_package(
        package_text,
        recipient_fingerprint=recipient_fp,
        recipient_passphrase="recipient-pass",
    )

    assert result.plaintext == "hello secure world"
    assert result.signature_valid is True
    assert result.sender_fingerprint == sender_fp


def test_create_and_decrypt_message_package_x25519():
    recipient_fp = _store_x25519_key("recipient-x", b"recipient-pass")

    package_text = create_message_package(
        "hello via x25519",
        recipient_fingerprint=recipient_fp,
    )

    result = decrypt_message_package(
        package_text,
        recipient_fingerprint=recipient_fp,
        recipient_passphrase="recipient-pass",
    )

    assert result.plaintext == "hello via x25519"
    assert result.signature_valid is None
