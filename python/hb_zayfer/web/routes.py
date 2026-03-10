"""API routes for the HB_Zayfer web interface."""

from __future__ import annotations

import base64
import json
import tempfile
from pathlib import Path
from typing import Optional

from fastapi import APIRouter, File, HTTPException, UploadFile
from fastapi.responses import StreamingResponse
from pydantic import BaseModel

import hb_zayfer as hbz

router = APIRouter()

# Maximum upload size: 256 MiB.
_MAX_UPLOAD_BYTES = 256 * 1024 * 1024


def _audit_safe(fn, *args, **kwargs) -> None:
    try:
        fn(*args, **kwargs)
    except Exception:
        pass


# ---------------------------------------------------------------------------
# Request / response models
# ---------------------------------------------------------------------------

class EncryptTextRequest(BaseModel):
    plaintext: str
    passphrase: str
    algorithm: str = "aes"


class EncryptTextResponse(BaseModel):
    ciphertext_b64: str


class DecryptTextRequest(BaseModel):
    ciphertext_b64: str
    passphrase: str


class DecryptTextResponse(BaseModel):
    plaintext: str


class KeygenRequest(BaseModel):
    algorithm: str  # rsa2048, rsa4096, ed25519, x25519, pgp
    label: str
    passphrase: str
    user_id: Optional[str] = None


class KeygenResponse(BaseModel):
    fingerprint: str
    algorithm: str
    label: str


class SignRequest(BaseModel):
    message_b64: str
    fingerprint: str
    passphrase: str
    algorithm: str = "ed25519"


class SignResponse(BaseModel):
    signature_b64: str


class VerifyRequest(BaseModel):
    message_b64: str
    signature_b64: str
    fingerprint: str
    algorithm: str = "ed25519"


class VerifyResponse(BaseModel):
    valid: bool


class ContactRequest(BaseModel):
    name: str
    email: Optional[str] = None
    notes: Optional[str] = None


class LinkKeyRequest(BaseModel):
    contact_name: str
    fingerprint: str


class KeyMetadataOut(BaseModel):
    fingerprint: str
    algorithm: str
    label: str
    created_at: str
    has_private: bool
    has_public: bool


class ContactOut(BaseModel):
    name: str
    email: Optional[str]
    key_fingerprints: list[str]
    notes: Optional[str]
    created_at: str


class VersionResponse(BaseModel):
    version: str


# ---------------------------------------------------------------------------
# Info
# ---------------------------------------------------------------------------

@router.get("/version", response_model=VersionResponse)
def get_version():
    return VersionResponse(version=hbz.version())


# ---------------------------------------------------------------------------
# Text encryption / decryption
# ---------------------------------------------------------------------------

@router.post("/encrypt/text", response_model=EncryptTextResponse)
def encrypt_text(req: EncryptTextRequest):
    try:
        encrypted = hbz.encrypt_data(
            req.plaintext.encode("utf-8"),
            algorithm=req.algorithm,
            wrapping="password",
            passphrase=req.passphrase.encode("utf-8"),
        )
        _audit_safe(
            hbz.audit_log_file_encrypted,
            req.algorithm.upper(),
            "web:text",
            len(req.plaintext.encode("utf-8")),
            "source=web, endpoint=/api/encrypt/text",
        )
        return EncryptTextResponse(ciphertext_b64=base64.b64encode(encrypted).decode())
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.post("/decrypt/text", response_model=DecryptTextResponse)
def decrypt_text(req: DecryptTextRequest):
    try:
        data = base64.b64decode(req.ciphertext_b64)
        plaintext = hbz.decrypt_data(data, passphrase=req.passphrase.encode("utf-8"))
        _audit_safe(
            hbz.audit_log_file_decrypted,
            "WEB:TEXT",
            "web:text",
            len(plaintext),
            "source=web, endpoint=/api/decrypt/text",
        )
        return DecryptTextResponse(plaintext=plaintext.decode("utf-8", errors="replace"))
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


# ---------------------------------------------------------------------------
# Key generation
# ---------------------------------------------------------------------------

@router.post("/keygen", response_model=KeygenResponse)
def generate_key(req: KeygenRequest):
    try:
        ks = hbz.KeyStore()
        pw = req.passphrase.encode("utf-8")

        if req.algorithm in ("rsa2048", "rsa4096"):
            bits = 2048 if req.algorithm == "rsa2048" else 4096
            priv_pem, pub_pem = hbz.rsa_generate(bits)
            fp = hbz.rsa_fingerprint(pub_pem)
            ks.store_private_key(fp, priv_pem.encode(), pw, req.algorithm, req.label)
            ks.store_public_key(fp, pub_pem.encode(), req.algorithm, req.label)
        elif req.algorithm == "ed25519":
            sk_pem, vk_pem = hbz.ed25519_generate()
            fp = hbz.ed25519_fingerprint(vk_pem)
            ks.store_private_key(fp, sk_pem.encode(), pw, req.algorithm, req.label)
            ks.store_public_key(fp, vk_pem.encode(), req.algorithm, req.label)
        elif req.algorithm == "x25519":
            sk_raw, pk_raw = hbz.x25519_generate()
            fp = hbz.x25519_fingerprint(pk_raw)
            ks.store_private_key(fp, sk_raw, pw, req.algorithm, req.label)
            ks.store_public_key(fp, pk_raw, req.algorithm, req.label)
        elif req.algorithm == "pgp":
            uid = req.user_id or req.label
            pub_arm, sec_arm = hbz.pgp_generate(uid)
            fp = hbz.pgp_fingerprint(pub_arm)
            ks.store_private_key(fp, sec_arm.encode(), pw, req.algorithm, req.label)
            ks.store_public_key(fp, pub_arm.encode(), req.algorithm, req.label)
        else:
            raise HTTPException(status_code=400, detail=f"Unknown algorithm: {req.algorithm}")

        _audit_safe(hbz.audit_log_key_generated, req.algorithm.upper(), fp, "source=web, endpoint=/api/keygen")
        return KeygenResponse(fingerprint=fp, algorithm=req.algorithm, label=req.label)
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# ---------------------------------------------------------------------------
# Signing / Verification
# ---------------------------------------------------------------------------

@router.post("/sign", response_model=SignResponse)
def sign_message(req: SignRequest):
    try:
        ks = hbz.KeyStore()
        message = base64.b64decode(req.message_b64)
        priv_data = ks.load_private_key(req.fingerprint, req.passphrase.encode("utf-8"))

        if req.algorithm == "ed25519":
            sig = hbz.ed25519_sign(priv_data.decode(), message)
        elif req.algorithm == "rsa":
            sig = hbz.rsa_sign(priv_data.decode(), message)
        elif req.algorithm == "pgp":
            sig = hbz.pgp_sign(message, priv_data.decode())
        else:
            raise HTTPException(status_code=400, detail=f"Unknown algorithm: {req.algorithm}")

        _audit_safe(hbz.audit_log_data_signed, req.algorithm.upper(), req.fingerprint, "source=web, endpoint=/api/sign")
        return SignResponse(signature_b64=base64.b64encode(sig).decode())
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.post("/verify", response_model=VerifyResponse)
def verify_message(req: VerifyRequest):
    try:
        ks = hbz.KeyStore()
        message = base64.b64decode(req.message_b64)
        signature = base64.b64decode(req.signature_b64)
        pub_data = ks.load_public_key(req.fingerprint)

        if req.algorithm == "ed25519":
            valid = hbz.ed25519_verify(pub_data.decode(), message, signature)
        elif req.algorithm == "rsa":
            valid = hbz.rsa_verify(pub_data.decode(), message, signature)
        elif req.algorithm == "pgp":
            _, valid = hbz.pgp_verify(signature, pub_data.decode())
        else:
            raise HTTPException(status_code=400, detail=f"Unknown algorithm: {req.algorithm}")

        _audit_safe(hbz.audit_log_signature_verified, req.algorithm.upper(), req.fingerprint, bool(valid))
        return VerifyResponse(valid=valid)
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


# ---------------------------------------------------------------------------
# Key management
# ---------------------------------------------------------------------------

@router.get("/keys", response_model=list[KeyMetadataOut])
def list_keys():
    try:
        ks = hbz.KeyStore()
        return [
            KeyMetadataOut(
                fingerprint=k.fingerprint,
                algorithm=k.algorithm,
                label=k.label,
                created_at=k.created_at,
                has_private=k.has_private,
                has_public=k.has_public,
            )
            for k in ks.list_keys()
        ]
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.delete("/keys/{fingerprint}")
def delete_key(fingerprint: str):
    try:
        ks = hbz.KeyStore()
        ks.delete_key(fingerprint)
        _audit_safe(hbz.audit_log_key_deleted, fingerprint, "source=web, endpoint=/api/keys/{fingerprint}")
        return {"status": "deleted"}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.get("/keys/{fingerprint}/public")
def export_public_key(fingerprint: str):
    try:
        ks = hbz.KeyStore()
        pub_data = ks.load_public_key(fingerprint)
        return {"fingerprint": fingerprint, "public_key_b64": base64.b64encode(pub_data).decode()}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


# ---------------------------------------------------------------------------
# Contacts
# ---------------------------------------------------------------------------

@router.get("/contacts", response_model=list[ContactOut])
def list_contacts():
    try:
        ks = hbz.KeyStore()
        return [
            ContactOut(
                name=c.name,
                email=c.email,
                key_fingerprints=c.key_fingerprints,
                notes=c.notes,
                created_at=c.created_at,
            )
            for c in ks.list_contacts()
        ]
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/contacts")
def add_contact(req: ContactRequest):
    try:
        ks = hbz.KeyStore()
        ks.add_contact(req.name, email=req.email, notes=req.notes)
        _audit_safe(hbz.audit_log_contact_added, req.name, "source=web, endpoint=/api/contacts")
        return {"status": "created", "name": req.name}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.delete("/contacts/{name}")
def remove_contact(name: str):
    try:
        ks = hbz.KeyStore()
        ks.remove_contact(name)
        _audit_safe(hbz.audit_log_contact_deleted, name, "source=web, endpoint=/api/contacts/{name}")
        return {"status": "deleted"}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.post("/contacts/link")
def link_key_to_contact(req: LinkKeyRequest):
    try:
        ks = hbz.KeyStore()
        ks.associate_key_with_contact(req.contact_name, req.fingerprint)
        return {"status": "linked"}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


# ---------------------------------------------------------------------------
# File encryption / decryption
# ---------------------------------------------------------------------------

class EncryptFileResponse(BaseModel):
    filename: str
    size_bytes: int


@router.post("/encrypt/file")
async def encrypt_file(
    file: UploadFile = File(...),
    passphrase: str = "",
    algorithm: str = "aes",
):
    """Encrypt an uploaded file and return the encrypted .hbzf result."""
    if not passphrase:
        raise HTTPException(status_code=400, detail="passphrase is required")

    with tempfile.TemporaryDirectory() as tmp:
        in_path = Path(tmp) / (file.filename or "upload")
        out_path = in_path.with_suffix(in_path.suffix + ".hbzf")

        # Read uploaded file with size limit
        content = await file.read()
        if len(content) > _MAX_UPLOAD_BYTES:
            raise HTTPException(
                status_code=413,
                detail=f"File too large (max {_MAX_UPLOAD_BYTES // (1024*1024)} MiB)",
            )
        in_path.write_bytes(content)

        try:
            hbz.encrypt_file(
                str(in_path),
                str(out_path),
                algorithm=algorithm,
                wrapping="password",
                passphrase=passphrase.encode("utf-8"),
            )
        except Exception as e:
            raise HTTPException(status_code=400, detail=str(e))

        _audit_safe(
            hbz.audit_log_file_encrypted,
            algorithm.upper(),
            file.filename,
            len(content),
            "source=web, endpoint=/api/encrypt/file",
        )

        encrypted = out_path.read_bytes()

    def _iter():
        yield encrypted

    return StreamingResponse(
        _iter(),
        media_type="application/octet-stream",
        headers={
            "Content-Disposition": f'attachment; filename="{file.filename or "encrypted"}.hbzf"',
            "Content-Length": str(len(encrypted)),
        },
    )


@router.post("/decrypt/file")
async def decrypt_file(
    file: UploadFile = File(...),
    passphrase: str = "",
):
    """Decrypt an uploaded .hbzf file and return the plaintext result."""
    if not passphrase:
        raise HTTPException(status_code=400, detail="passphrase is required")

    with tempfile.TemporaryDirectory() as tmp:
        in_path = Path(tmp) / (file.filename or "upload.hbzf")
        # Strip .hbzf suffix for output name
        out_name = in_path.stem if in_path.suffix == ".hbzf" else in_path.name + ".dec"
        out_path = Path(tmp) / out_name

        content = await file.read()
        if len(content) > _MAX_UPLOAD_BYTES:
            raise HTTPException(
                status_code=413,
                detail=f"File too large (max {_MAX_UPLOAD_BYTES // (1024*1024)} MiB)",
            )
        in_path.write_bytes(content)

        try:
            hbz.decrypt_file(
                str(in_path),
                str(out_path),
                passphrase=passphrase.encode("utf-8"),
            )
        except Exception as e:
            raise HTTPException(status_code=400, detail=str(e))

        decrypted = out_path.read_bytes()

        _audit_safe(
            hbz.audit_log_file_decrypted,
            "WEB:FILE",
            file.filename,
            len(decrypted),
            "source=web, endpoint=/api/decrypt/file",
        )

    def _iter():
        yield decrypted

    return StreamingResponse(
        _iter(),
        media_type="application/octet-stream",
        headers={
            "Content-Disposition": f'attachment; filename="{out_name}"',
            "Content-Length": str(len(decrypted)),
        },
    )


# ---------------------------------------------------------------------------
# Audit log
# ---------------------------------------------------------------------------

class AuditEntryOut(BaseModel):
    timestamp: str
    operation: str
    prev_hash: Optional[str]
    entry_hash: str
    note: Optional[str]


class AuditVerifyResponse(BaseModel):
    valid: bool


@router.get("/audit/recent", response_model=list[AuditEntryOut])
def audit_recent(limit: int = 50):
    """Return the most recent audit log entries."""
    try:
        logger = hbz.AuditLogger()
        entries = logger.recent_entries(limit)
        return [
            AuditEntryOut(
                timestamp=e.timestamp,
                operation=e.operation,
                prev_hash=e.prev_hash,
                entry_hash=e.entry_hash,
                note=e.note,
            )
            for e in entries
        ]
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/audit/verify", response_model=AuditVerifyResponse)
def audit_verify():
    """Verify audit log hash-chain integrity."""
    try:
        logger = hbz.AuditLogger()
        return AuditVerifyResponse(valid=logger.verify_integrity())
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/audit/count")
def audit_count():
    """Return total number of audit entries."""
    try:
        logger = hbz.AuditLogger()
        return {"count": logger.entry_count()}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/audit/export")
def audit_export(destination: str):
    """Export the audit log to a given path on the server."""
    # Path traversal protection: resolve and restrict to home directory
    dest = Path(destination).expanduser().resolve()
    home = Path.home().resolve()
    if not str(dest).startswith(str(home)):
        raise HTTPException(status_code=400, detail="destination must be within user's home directory")
    try:
        logger = hbz.AuditLogger()
        logger.export(str(dest))
        return {"status": "exported", "destination": str(dest)}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


# ---------------------------------------------------------------------------
# Backup & Restore
# ---------------------------------------------------------------------------

class BackupRequest(BaseModel):
    output_path: str
    passphrase: str
    label: Optional[str] = None


class BackupManifestOut(BaseModel):
    created_at: str
    private_key_count: int
    public_key_count: int
    contact_count: int
    version: int
    label: Optional[str]
    integrity_hash: str


class RestoreRequest(BaseModel):
    backup_path: str
    passphrase: str


@router.post("/backup/create", response_model=BackupManifestOut)
def create_backup(req: BackupRequest):
    """Create an encrypted backup of the keyring."""
    # Path traversal protection
    out = Path(req.output_path).expanduser().resolve()
    home = Path.home().resolve()
    if not str(out).startswith(str(home)):
        raise HTTPException(status_code=400, detail="output_path must be within user's home directory")
    try:
        ks = hbz.KeyStore()
        ks.create_backup(str(out), req.passphrase.encode("utf-8"), req.label)
        manifest = ks.verify_backup(str(out), req.passphrase.encode("utf-8"))
        return BackupManifestOut(
            created_at=manifest.created_at,
            private_key_count=manifest.private_key_count,
            public_key_count=manifest.public_key_count,
            contact_count=manifest.contact_count,
            version=manifest.version,
            label=manifest.label,
            integrity_hash=manifest.integrity_hash,
        )
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.post("/backup/verify", response_model=BackupManifestOut)
def verify_backup(req: RestoreRequest):
    """Verify a backup file without restoring it."""
    bpath = Path(req.backup_path).expanduser().resolve()
    home = Path.home().resolve()
    if not str(bpath).startswith(str(home)):
        raise HTTPException(status_code=400, detail="backup_path must be within user's home directory")
    try:
        ks = hbz.KeyStore()
        manifest = ks.verify_backup(str(bpath), req.passphrase.encode("utf-8"))
        return BackupManifestOut(
            created_at=manifest.created_at,
            private_key_count=manifest.private_key_count,
            public_key_count=manifest.public_key_count,
            contact_count=manifest.contact_count,
            version=manifest.version,
            label=manifest.label,
            integrity_hash=manifest.integrity_hash,
        )
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.post("/backup/restore", response_model=BackupManifestOut)
def restore_backup(req: RestoreRequest):
    """Restore a backup, importing keys and contacts."""
    bpath = Path(req.backup_path).expanduser().resolve()
    home = Path.home().resolve()
    if not str(bpath).startswith(str(home)):
        raise HTTPException(status_code=400, detail="backup_path must be within user's home directory")
    try:
        ks = hbz.KeyStore()
        manifest = ks.restore_backup(str(bpath), req.passphrase.encode("utf-8"))
        return BackupManifestOut(
            created_at=manifest.created_at,
            private_key_count=manifest.private_key_count,
            public_key_count=manifest.public_key_count,
            contact_count=manifest.contact_count,
            version=manifest.version,
            label=manifest.label,
            integrity_hash=manifest.integrity_hash,
        )
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


# ---------------------------------------------------------------------------
# Config — standalone load/save (no GUI dependency)
# ---------------------------------------------------------------------------

def _web_config_path() -> Path:
    """Return path to config.json inside the keystore directory."""
    try:
        ks = hbz.KeyStore()
        return Path(ks.base_path) / "config.json"
    except Exception:
        return Path.home() / ".hb_zayfer" / "config.json"


_CONFIG_DEFAULTS = {
    "cipher": "AES-256-GCM",
    "kdf": "Argon2id",
    "argon2_memory_mib": 64,
    "argon2_iterations": 3,
    "dark_mode": True,
    "clipboard_auto_clear": 30,
}


def _web_load_config() -> dict:
    """Load persisted settings, returning defaults on any error."""
    p = _web_config_path()
    cfg = dict(_CONFIG_DEFAULTS)
    if p.exists():
        try:
            with open(p, encoding="utf-8") as f:
                cfg.update(json.load(f))
        except Exception:
            pass
    return cfg


def _web_save_config(cfg: dict) -> None:
    """Persist settings to config.json (atomic write)."""
    p = _web_config_path()
    p.parent.mkdir(parents=True, exist_ok=True)
    tmp = p.with_suffix(".tmp")
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(cfg, f, indent=2)
    tmp.rename(p)


@router.get("/config")
def get_config():
    """Return all configuration settings."""
    try:
        return _web_load_config()
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/config/{key}")
def get_config_key(key: str):
    """Return a single configuration value."""
    try:
        cfg = _web_load_config()
        if key not in cfg:
            raise HTTPException(status_code=404, detail=f"Unknown config key: {key}")
        return {"key": key, "value": cfg[key]}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


class ConfigUpdateRequest(BaseModel):
    value: object


@router.put("/config/{key}")
def set_config_key(key: str, req: ConfigUpdateRequest):
    """Set a configuration value."""
    try:
        cfg = _web_load_config()
        cfg[key] = req.value
        _web_save_config(cfg)
        return {"key": key, "value": req.value}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


# ---------------------------------------------------------------------------
# Password generation
# ---------------------------------------------------------------------------

class PassgenRequest(BaseModel):
    length: int = 20
    words: int | None = None
    separator: str = "-"
    exclude: str = ""


@router.post("/passgen")
def generate_password(req: PassgenRequest):
    """Generate a random password or passphrase."""
    try:
        if req.words:
            value = hbz.generate_passphrase(req.words, req.separator)
            entropy = hbz.passphrase_entropy(req.words)
            return {"type": "passphrase", "value": value, "entropy_bits": entropy}
        else:
            value = hbz.generate_password(
                length=req.length,
                uppercase=True,
                lowercase=True,
                digits=True,
                symbols=True,
                exclude=req.exclude,
            )
            entropy = hbz.password_entropy(
                length=req.length,
                uppercase=True,
                lowercase=True,
                digits=True,
                symbols=True,
            )
            return {"type": "password", "value": value, "entropy_bits": entropy}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


# ---------------------------------------------------------------------------
# Shamir's Secret Sharing
# ---------------------------------------------------------------------------

class ShamirSplitRequest(BaseModel):
    secret_b64: str
    shares: int = 5
    threshold: int = 3


@router.post("/shamir/split")
def shamir_split(req: ShamirSplitRequest):
    """Split a secret into Shamir shares."""
    try:
        secret = base64.b64decode(req.secret_b64)
        share_list = hbz.shamir_split(secret, req.shares, req.threshold)
        return {"shares": share_list, "total": req.shares, "threshold": req.threshold}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


class ShamirCombineRequest(BaseModel):
    shares: list[str]


@router.post("/shamir/combine")
def shamir_combine(req: ShamirCombineRequest):
    """Combine Shamir shares to recover the secret."""
    try:
        secret = hbz.shamir_combine(req.shares)
        return {"secret_b64": base64.b64encode(secret).decode()}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


# ---------------------------------------------------------------------------
# QR Key Exchange
# ---------------------------------------------------------------------------

class QREncodeRequest(BaseModel):
    algorithm: str
    public_key_b64: str
    label: str | None = None


@router.post("/qr/encode")
def qr_encode_key(req: QREncodeRequest):
    """Encode a public key as an hbzf-key:// URI."""
    try:
        pub_bytes = base64.b64decode(req.public_key_b64)
        uri = hbz.qr_encode_key_uri(req.algorithm, pub_bytes, req.label)
        return {"uri": uri}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


class QRDecodeRequest(BaseModel):
    uri: str


@router.post("/qr/decode")
def qr_decode_key(req: QRDecodeRequest):
    """Decode an hbzf-key:// URI into its components."""
    try:
        algo, key_bytes, label = hbz.qr_decode_key_uri(req.uri)
        return {
            "algorithm": algo,
            "public_key_b64": base64.b64encode(key_bytes).decode(),
            "label": label,
        }
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))
