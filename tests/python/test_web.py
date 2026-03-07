"""Tests for the HB Zayfer web API routes.

Run with:  pytest tests/python/test_web.py -v
Requires : maturin develop  (to build native module first)
"""

from __future__ import annotations

from pathlib import Path

import pytest

import hb_zayfer as hbz


pytest.importorskip("httpx")
pytest.importorskip("fastapi")

from fastapi.testclient import TestClient  # noqa: E402
from hb_zayfer.web.app import create_app  # noqa: E402


@pytest.fixture(autouse=True)
def _isolated_keystore(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("HB_ZAYFER_HOME", str(tmp_path))


@pytest.fixture()
def client():
    app = create_app()
    return TestClient(app)


# ===========================================================================
# Version
# ===========================================================================

def test_version(client: TestClient):
    r = client.get("/api/version")
    assert r.status_code == 200
    assert "version" in r.json()


# ===========================================================================
# Encrypt / Decrypt text
# ===========================================================================

def test_encrypt_decrypt_text(client: TestClient):
    # Encrypt
    r = client.post("/api/encrypt/text", json={
        "plaintext": "hello web",
        "passphrase": "secret",
        "algorithm": "aes",
    })
    assert r.status_code == 200
    ct_b64 = r.json()["ciphertext_b64"]
    assert len(ct_b64) > 0

    # Decrypt
    r = client.post("/api/decrypt/text", json={
        "ciphertext_b64": ct_b64,
        "passphrase": "secret",
    })
    assert r.status_code == 200
    assert r.json()["plaintext"] == "hello web"


def test_decrypt_wrong_passphrase(client: TestClient):
    r = client.post("/api/encrypt/text", json={
        "plaintext": "data",
        "passphrase": "right",
    })
    ct_b64 = r.json()["ciphertext_b64"]

    r = client.post("/api/decrypt/text", json={
        "ciphertext_b64": ct_b64,
        "passphrase": "wrong",
    })
    assert r.status_code == 400


# ===========================================================================
# Key Generation
# ===========================================================================

def test_keygen_ed25519(client: TestClient):
    r = client.post("/api/keygen", json={
        "algorithm": "ed25519",
        "label": "test-ed",
        "passphrase": "pass",
    })
    assert r.status_code == 200
    data = r.json()
    assert data["algorithm"] == "ed25519"
    assert len(data["fingerprint"]) > 0


def test_keygen_and_list(client: TestClient):
    client.post("/api/keygen", json={
        "algorithm": "ed25519",
        "label": "key1",
        "passphrase": "p",
    })
    r = client.get("/api/keys")
    assert r.status_code == 200
    keys = r.json()
    assert len(keys) >= 1
    assert keys[0]["label"] == "key1"


# ===========================================================================
# Key Delete
# ===========================================================================

def test_delete_key(client: TestClient):
    r = client.post("/api/keygen", json={
        "algorithm": "ed25519",
        "label": "delme",
        "passphrase": "p",
    })
    fp = r.json()["fingerprint"]

    r = client.delete(f"/api/keys/{fp}")
    assert r.status_code == 200

    r = client.get("/api/keys")
    assert all(k["fingerprint"] != fp for k in r.json())


# ===========================================================================
# Contacts
# ===========================================================================

def test_contacts_crud(client: TestClient):
    # Add
    r = client.post("/api/contacts", json={"name": "Alice", "email": "a@b.com"})
    assert r.status_code == 200

    # List
    r = client.get("/api/contacts")
    assert r.status_code == 200
    cs = r.json()
    assert len(cs) == 1
    assert cs[0]["name"] == "Alice"

    # Remove
    r = client.delete("/api/contacts/Alice")
    assert r.status_code == 200

    r = client.get("/api/contacts")
    assert len(r.json()) == 0


def test_link_key_to_contact(client: TestClient):
    # Create key
    r = client.post("/api/keygen", json={
        "algorithm": "ed25519",
        "label": "link-test",
        "passphrase": "p",
    })
    fp = r.json()["fingerprint"]

    # Create contact
    client.post("/api/contacts", json={"name": "Bob"})

    # Link
    r = client.post("/api/contacts/link", json={
        "contact_name": "Bob",
        "fingerprint": fp,
    })
    assert r.status_code == 200

    # Verify
    r = client.get("/api/contacts")
    bob = r.json()[0]
    assert fp in bob["key_fingerprints"]
