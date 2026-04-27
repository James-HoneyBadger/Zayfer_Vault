"""Tests for the Zayfer Vault web API routes.

Run with:  pytest tests/python/test_web.py -v
Requires : maturin develop  (to build native module first)
"""

from __future__ import annotations

import base64
import io
from pathlib import Path

import pytest

pytest.importorskip("httpx")
pytest.importorskip("fastapi")

from fastapi.testclient import TestClient  # noqa: E402
from hb_zayfer.web.app import create_app  # noqa: E402


@pytest.fixture(autouse=True)
def _isolated_keystore(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("HB_ZAYFER_HOME", str(tmp_path))
    # Ensure no auth token by default
    monkeypatch.delenv("HB_ZAYFER_API_TOKEN", raising=False)


@pytest.fixture()
def client():
    app = create_app()
    return TestClient(app)


def test_auth_token_required_when_configured(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("HB_ZAYFER_API_TOKEN", "top-secret")
    app = create_app()

    with TestClient(app) as secured_client:
        r = secured_client.get("/api/config")
        assert r.status_code == 401

        r = secured_client.get(
            "/api/config",
            headers={"Authorization": "Bearer top-secret"},
        )
        assert r.status_code == 200


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


# ===========================================================================
# Sign / Verify
# ===========================================================================

def _make_ed25519_key(client: TestClient) -> str:
    """Helper: generate an ed25519 key and return its fingerprint."""
    r = client.post("/api/keygen", json={
        "algorithm": "ed25519",
        "label": "sign-test",
        "passphrase": "p",
    })
    assert r.status_code == 200
    return r.json()["fingerprint"]


def test_sign_verify_ed25519(client: TestClient):
    fp = _make_ed25519_key(client)
    msg = base64.b64encode(b"hello sign").decode()

    r = client.post("/api/sign", json={
        "message_b64": msg,
        "fingerprint": fp,
        "passphrase": "p",
        "algorithm": "ed25519",
    })
    assert r.status_code == 200
    sig_b64 = r.json()["signature_b64"]
    assert len(sig_b64) > 0

    r = client.post("/api/verify", json={
        "message_b64": msg,
        "signature_b64": sig_b64,
        "fingerprint": fp,
        "algorithm": "ed25519",
    })
    assert r.status_code == 200
    assert r.json()["valid"] is True


def test_verify_bad_signature(client: TestClient):
    fp = _make_ed25519_key(client)
    msg = base64.b64encode(b"data").decode()
    bad_sig = base64.b64encode(b"\x00" * 64).decode()

    r = client.post("/api/verify", json={
        "message_b64": msg,
        "signature_b64": bad_sig,
        "fingerprint": fp,
        "algorithm": "ed25519",
    })
    # Should either return valid=False or 400 depending on implementation
    assert r.status_code in (200, 400)
    if r.status_code == 200:
        assert r.json()["valid"] is False


def test_sign_unknown_algorithm(client: TestClient):
    fp = _make_ed25519_key(client)
    msg = base64.b64encode(b"hello").decode()
    r = client.post("/api/sign", json={
        "message_b64": msg,
        "fingerprint": fp,
        "passphrase": "p",
        "algorithm": "unknown_algo",
    })
    assert r.status_code == 400


# ===========================================================================
# Export public key
# ===========================================================================

def test_export_public_key(client: TestClient):
    fp = _make_ed25519_key(client)
    r = client.get(f"/api/keys/{fp}/public")
    assert r.status_code == 200
    data = r.json()
    assert data["fingerprint"] == fp
    assert len(data["public_key_b64"]) > 0
    # Must decode as valid base64
    base64.b64decode(data["public_key_b64"])


def test_export_nonexistent_key(client: TestClient):
    r = client.get("/api/keys/nonexistent/public")
    assert r.status_code == 400


# ===========================================================================
# File encryption / decryption
# ===========================================================================

def test_encrypt_decrypt_file(client: TestClient):
    content = b"secret file contents here"

    # Encrypt (passphrase and algorithm are query params, not form data)
    r = client.post(
        "/api/encrypt/file?passphrase=filepass&algorithm=aes",
        files={"file": ("test.txt", io.BytesIO(content), "text/plain")},
    )
    assert r.status_code == 200
    encrypted = r.content
    assert len(encrypted) > 0
    assert encrypted != content  # Must be different

    # Decrypt
    r = client.post(
        "/api/decrypt/file?passphrase=filepass",
        files={"file": ("test.txt.hbzf", io.BytesIO(encrypted), "application/octet-stream")},
    )
    assert r.status_code == 200
    assert r.content == content


def test_encrypt_file_no_passphrase(client: TestClient):
    r = client.post(
        "/api/encrypt/file?passphrase=&algorithm=aes",
        files={"file": ("test.txt", io.BytesIO(b"data"), "text/plain")},
    )
    assert r.status_code == 400


def test_decrypt_file_wrong_passphrase(client: TestClient):
    content = b"data"
    r = client.post(
        "/api/encrypt/file?passphrase=correct&algorithm=aes",
        files={"file": ("f.txt", io.BytesIO(content), "text/plain")},
    )
    encrypted = r.content

    r = client.post(
        "/api/decrypt/file?passphrase=wrong",
        files={"file": ("f.txt.hbzf", io.BytesIO(encrypted), "application/octet-stream")},
    )
    assert r.status_code == 400


def test_encrypt_file_size_limit(client: TestClient, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr("hb_zayfer.web.routes._MAX_UPLOAD_BYTES", 8)
    r = client.post(
        "/api/encrypt/file?passphrase=filepass&algorithm=aes",
        files={"file": ("too-big.txt", io.BytesIO(b"123456789"), "text/plain")},
    )
    assert r.status_code == 413


# ===========================================================================
# Audit log
# ===========================================================================

def test_audit_recent(client: TestClient):
    # Generate a key to create at least one audit entry
    client.post("/api/keygen", json={
        "algorithm": "ed25519", "label": "audit-test", "passphrase": "p",
    })
    r = client.get("/api/audit/recent?limit=10")
    assert r.status_code == 200
    entries = r.json()
    assert isinstance(entries, list)


def test_audit_verify(client: TestClient):
    r = client.get("/api/audit/verify")
    assert r.status_code == 200
    data = r.json()
    assert "valid" in data
    assert isinstance(data["valid"], bool)


def test_audit_count(client: TestClient):
    r = client.get("/api/audit/count")
    assert r.status_code == 200
    data = r.json()
    assert "count" in data
    assert isinstance(data["count"], int)
    assert data["count"] >= 0


def test_audit_export(client: TestClient, tmp_path: Path):
    # Use a path within the user's home directory
    home = Path.home()
    dest = str(home / ".hb_zayfer_test_audit_export.json")
    try:
        r = client.post("/api/audit/export", params={"destination": dest})
        assert r.status_code == 200
        assert r.json()["status"] == "exported"
    finally:
        Path(dest).unlink(missing_ok=True)


def test_audit_export_path_traversal(client: TestClient):
    """Path traversal attempt should be rejected."""
    r = client.post("/api/audit/export", params={"destination": "/tmp/../../etc/passwd"})
    assert r.status_code == 400
    assert "home directory" in r.json()["detail"].lower()


def test_audit_export_home_prefix_bypass_rejected(client: TestClient):
    home = Path.home().resolve()
    bypass = home.parent / f"{home.name}_evil" / "audit.json"
    r = client.post("/api/audit/export", params={"destination": str(bypass)})
    assert r.status_code == 400
    assert "home directory" in r.json()["detail"].lower()


# ===========================================================================
# Backup / Restore
# ===========================================================================

def test_backup_create_verify_restore(client: TestClient, tmp_path: Path):
    # Generate a key so the backup isn't empty
    client.post("/api/keygen", json={
        "algorithm": "ed25519", "label": "bk-key", "passphrase": "p",
    })
    client.post("/api/contacts", json={"name": "BkContact"})

    # Use a path within the user's home directory
    home = Path.home()
    backup_path = str(home / ".hb_zayfer_test_backup.hbzf")

    try:
        # Create backup
        r = client.post("/api/backup/create", json={
            "output_path": backup_path,
            "passphrase": "bkpass",
            "label": "test-backup",
        })
        assert r.status_code == 200
        m = r.json()
        assert m["private_key_count"] >= 1
        assert m["contact_count"] >= 1
        assert m["label"] == "test-backup"

        # Verify backup
        r = client.post("/api/backup/verify", json={
            "backup_path": backup_path,
            "passphrase": "bkpass",
        })
        assert r.status_code == 200
        assert r.json()["integrity_hash"] == m["integrity_hash"]

        # Restore backup
        r = client.post("/api/backup/restore", json={
            "backup_path": backup_path,
            "passphrase": "bkpass",
        })
        assert r.status_code == 200
    finally:
        Path(backup_path).unlink(missing_ok=True)


def test_backup_path_traversal(client: TestClient):
    r = client.post("/api/backup/create", json={
        "output_path": "/tmp/../../etc/evil",
        "passphrase": "p",
    })
    assert r.status_code == 400
    assert "home directory" in r.json()["detail"].lower()


def test_backup_home_prefix_bypass_rejected(client: TestClient):
    home = Path.home().resolve()
    bypass = home.parent / f"{home.name}_evil" / "backup.hbzf"
    r = client.post("/api/backup/create", json={
        "output_path": str(bypass),
        "passphrase": "p",
    })
    assert r.status_code == 400
    assert "home directory" in r.json()["detail"].lower()


# ===========================================================================
# Configuration
# ===========================================================================

def test_config_get(client: TestClient):
    r = client.get("/api/config")
    assert r.status_code == 200
    assert isinstance(r.json(), dict)


def test_config_get_set_key(client: TestClient):
    # Set a value
    r = client.put("/api/config/default_algorithm", json={"value": "chacha20"})
    assert r.status_code == 200
    assert r.json()["value"] == "chacha20"

    # Read it back
    r = client.get("/api/config/default_algorithm")
    assert r.status_code == 200
    assert r.json()["value"] == "chacha20"


def test_config_get_unknown_key(client: TestClient):
    r = client.get("/api/config/nonexistent_key_xyz")
    assert r.status_code == 404


# ===========================================================================
# Password generation
# ===========================================================================

def test_passgen_password(client: TestClient):
    r = client.post("/api/passgen", json={"length": 24})
    assert r.status_code == 200
    data = r.json()
    assert data["type"] == "password"
    assert len(data["value"]) == 24
    assert data["entropy_bits"] > 0


def test_passgen_passphrase(client: TestClient):
    r = client.post("/api/passgen", json={"words": 4, "separator": "-"})
    assert r.status_code == 200
    data = r.json()
    assert data["type"] == "passphrase"
    assert "-" in data["value"]
    assert data["entropy_bits"] > 0


# ===========================================================================
# Shamir's Secret Sharing
# ===========================================================================

def test_shamir_split_combine(client: TestClient):
    secret = b"my-secret-data"
    secret_b64 = base64.b64encode(secret).decode()

    # Split
    r = client.post("/api/shamir/split", json={
        "secret_b64": secret_b64,
        "shares": 5,
        "threshold": 3,
    })
    assert r.status_code == 200
    data = r.json()
    assert data["total"] == 5
    assert data["threshold"] == 3
    shares = data["shares"]
    assert len(shares) == 5

    # Combine (using exactly threshold shares)
    r = client.post("/api/shamir/combine", json={"shares": shares[:3]})
    assert r.status_code == 200
    recovered = base64.b64decode(r.json()["secret_b64"])
    assert recovered == secret


def test_shamir_below_threshold_fails(client: TestClient):
    secret_b64 = base64.b64encode(b"secret").decode()
    r = client.post("/api/shamir/split", json={
        "secret_b64": secret_b64,
        "shares": 5,
        "threshold": 3,
    })
    shares = r.json()["shares"]

    # Use only 2 shares (below threshold of 3) — should recover wrong data
    r = client.post("/api/shamir/combine", json={"shares": shares[:2]})
    # The combine endpoint doesn't error, but the data should be invalid
    if r.status_code == 200:
        recovered = base64.b64decode(r.json()["secret_b64"])
        assert recovered != b"secret"  # Should mismatch


# ===========================================================================
# QR Key Exchange
# ===========================================================================

def test_qr_encode_decode(client: TestClient):
    pub_key = b"\x01\x02\x03\x04\x05"
    pub_b64 = base64.b64encode(pub_key).decode()

    # Encode
    r = client.post("/api/qr/encode", json={
        "algorithm": "ed25519",
        "public_key_b64": pub_b64,
        "label": "Alice",
    })
    assert r.status_code == 200
    uri = r.json()["uri"]
    assert uri.startswith("hbzf-key://")
    assert "ed25519" in uri

    # Decode
    r = client.post("/api/qr/decode", json={"uri": uri})
    assert r.status_code == 200
    data = r.json()
    assert data["algorithm"] == "ed25519"
    assert data["label"] == "Alice"
    # Round-trip: decoded public_key should match
    decoded_key = base64.b64decode(data["public_key_b64"])
    assert decoded_key == pub_key


def test_qr_decode_invalid_uri(client: TestClient):
    r = client.post("/api/qr/decode", json={"uri": "not-a-valid-uri"})
    assert r.status_code == 400


# ===========================================================================
# Rate Limiting
# ===========================================================================

def test_rate_limit_headers(client: TestClient):
    """Responses should include rate-limit headers."""
    r = client.get("/api/version")
    assert r.status_code == 200
    assert "X-RateLimit-Limit" in r.headers
    assert "X-RateLimit-Remaining" in r.headers


def test_rate_limiter_isolated_per_app_instance(monkeypatch: pytest.MonkeyPatch):
    """A fresh app instance should start with a fresh limiter window."""
    monkeypatch.setenv("HB_ZAYFER_RATE_LIMIT", "1")
    monkeypatch.setenv("HB_ZAYFER_RATE_WINDOW", "60")

    app1 = create_app()
    with TestClient(app1) as c1:
        assert c1.get("/api/version").status_code == 200
        assert c1.get("/api/version").status_code == 429

    app2 = create_app()
    with TestClient(app2) as c2:
        r = c2.get("/api/version")
        assert r.status_code == 200
        assert r.headers["X-RateLimit-Limit"] == "1"


# ===========================================================================
# Authentication middleware
# ===========================================================================

def test_auth_required_when_token_set(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """When HB_ZAYFER_API_TOKEN is set, requests without token get 401."""
    monkeypatch.setenv("HB_ZAYFER_API_TOKEN", "test-secret-token")
    # Must re-import to pick up env var at module level
    import importlib

    from hb_zayfer.web import app as app_module
    importlib.reload(app_module)
    try:
        test_app = app_module.create_app()
        c = TestClient(test_app)

        # No token → 401
        r = c.get("/api/version")
        assert r.status_code == 401

        # Wrong token → 401
        r = c.get("/api/version", headers={"Authorization": "Bearer wrong-token"})
        assert r.status_code == 401

        # Correct token → 200
        r = c.get("/api/version", headers={"Authorization": "Bearer test-secret-token"})
        assert r.status_code == 200
    finally:
        # Reset module state for other tests
        monkeypatch.delenv("HB_ZAYFER_API_TOKEN", raising=False)
        importlib.reload(app_module)
