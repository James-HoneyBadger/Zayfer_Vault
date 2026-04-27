"""API routes for the HB_Zayfer web interface."""

from __future__ import annotations

import base64
import re
import tempfile
from pathlib import Path

from fastapi import APIRouter, File, HTTPException, UploadFile
from fastapi.responses import StreamingResponse
from pydantic import BaseModel

import hb_zayfer as hbz
from hb_zayfer.services import (
    AppInfo,
    AppPaths,
    AuditService,
    BackupService,
    ConfigService,
    CryptoService,
    KeyService,
    SignatureService,
)

router = APIRouter()

# Maximum upload size: 256 MiB.
_MAX_UPLOAD_BYTES = 256 * 1024 * 1024


def _sanitize_filename(name: str | None, fallback: str = "file") -> str:
    """Strip path separators and control chars from a user-supplied filename."""
    if not name:
        return fallback
    # Keep only the basename (no directory traversal)
    name = Path(name).name
    # Remove control characters and quotes that could break Content-Disposition
    name = re.sub(r'[\x00-\x1f"\\]', "_", name)
    return name or fallback


def _audit_safe(fn, *args, **kwargs) -> None:
    try:
        fn(*args, **kwargs)
    except Exception:
        pass


def _require_home_path(raw_path: str, field_name: str) -> Path:
    """Resolve a user-supplied path and ensure it stays within the home dir."""
    try:
        return AppPaths.current().resolve_user_path(raw_path, field_name)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


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
    user_id: str | None = None


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
    email: str | None = None
    notes: str | None = None


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
    email: str | None
    key_fingerprints: list[str]
    notes: str | None
    created_at: str


class VersionResponse(BaseModel):
    version: str


# ---------------------------------------------------------------------------
# Info
# ---------------------------------------------------------------------------


@router.get("/version", response_model=VersionResponse)
def get_version():
    return VersionResponse(version=AppInfo.current().version)


# ---------------------------------------------------------------------------
# Text encryption / decryption
# ---------------------------------------------------------------------------


@router.post("/encrypt/text", response_model=EncryptTextResponse)
def encrypt_text(req: EncryptTextRequest):
    try:
        ciphertext_b64 = CryptoService.encrypt_text(req.plaintext, req.passphrase, req.algorithm)
        return EncryptTextResponse(ciphertext_b64=ciphertext_b64)
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e)) from e


@router.post("/decrypt/text", response_model=DecryptTextResponse)
def decrypt_text(req: DecryptTextRequest):
    try:
        plaintext = CryptoService.decrypt_text(req.ciphertext_b64, req.passphrase)
        return DecryptTextResponse(plaintext=plaintext)
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e)) from e


# ---------------------------------------------------------------------------
# Key generation
# ---------------------------------------------------------------------------


@router.post("/keygen", response_model=KeygenResponse)
def generate_key(req: KeygenRequest):
    try:
        result = KeyService.generate_key(
            algorithm=req.algorithm,
            label=req.label,
            passphrase=req.passphrase.encode("utf-8"),
            user_id=req.user_id,
        )
        return KeygenResponse(
            fingerprint=result.fingerprint,
            algorithm=result.algorithm,
            label=result.label,
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e)) from e
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e)) from e


# ---------------------------------------------------------------------------
# Signing / Verification
# ---------------------------------------------------------------------------


@router.post("/sign", response_model=SignResponse)
def sign_message(req: SignRequest):
    try:
        signature_b64 = SignatureService.sign_message(
            message_b64=req.message_b64,
            fingerprint=req.fingerprint,
            passphrase=req.passphrase,
            algorithm=req.algorithm,
        )
        return SignResponse(signature_b64=signature_b64)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e)) from e
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e)) from e


@router.post("/verify", response_model=VerifyResponse)
def verify_message(req: VerifyRequest):
    try:
        valid = SignatureService.verify_message(
            message_b64=req.message_b64,
            signature_b64=req.signature_b64,
            fingerprint=req.fingerprint,
            algorithm=req.algorithm,
        )
        return VerifyResponse(valid=valid)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e)) from e
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e)) from e


# ---------------------------------------------------------------------------
# Key management
# ---------------------------------------------------------------------------


@router.get("/keys", response_model=list[KeyMetadataOut])
def list_keys():
    try:
        return [
            KeyMetadataOut(
                fingerprint=k.fingerprint,
                algorithm=k.algorithm,
                label=k.label,
                created_at=k.created_at,
                has_private=k.has_private,
                has_public=k.has_public,
            )
            for k in KeyService.list_keys()
        ]
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e)) from e


@router.delete("/keys/{fingerprint}")
def delete_key(fingerprint: str):
    try:
        KeyService.delete_key(fingerprint)
        return {"status": "deleted"}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e)) from e


@router.get("/keys/{fingerprint}/public")
def export_public_key(fingerprint: str):
    try:
        pub_data = KeyService.load_public_key(fingerprint)
        return {"fingerprint": fingerprint, "public_key_b64": base64.b64encode(pub_data).decode()}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e)) from e


# ---------------------------------------------------------------------------
# Contacts
# ---------------------------------------------------------------------------


@router.get("/contacts", response_model=list[ContactOut])
def list_contacts():
    try:
        return [
            ContactOut(
                name=c.name,
                email=c.email,
                key_fingerprints=c.key_fingerprints,
                notes=c.notes,
                created_at=c.created_at,
            )
            for c in KeyService.list_contacts()
        ]
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e)) from e


@router.post("/contacts")
def add_contact(req: ContactRequest):
    try:
        KeyService.add_contact(req.name, email=req.email, notes=req.notes)
        return {"status": "created", "name": req.name}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e)) from e


@router.delete("/contacts/{name}")
def remove_contact(name: str):
    try:
        KeyService.remove_contact(name)
        return {"status": "deleted"}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e)) from e


@router.post("/contacts/link")
def link_key_to_contact(req: LinkKeyRequest):
    try:
        KeyService.link_key_to_contact(req.contact_name, req.fingerprint)
        return {"status": "linked"}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e)) from e


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
        safe_name = _sanitize_filename(file.filename, "upload")
        in_path = Path(tmp) / safe_name
        out_path = in_path.with_suffix(in_path.suffix + ".hbzf")

        # Read uploaded file with size limit
        content = await file.read()
        if len(content) > _MAX_UPLOAD_BYTES:
            raise HTTPException(
                status_code=413,
                detail=f"File too large (max {_MAX_UPLOAD_BYTES // (1024 * 1024)} MiB)",
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
            raise HTTPException(status_code=400, detail=str(e)) from e

        _audit_safe(
            hbz.audit_log_file_encrypted,
            algorithm.upper(),
            safe_name,
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
            "Content-Disposition": f'attachment; filename="{_sanitize_filename(file.filename, "encrypted")}.hbzf"',
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
        safe_name = _sanitize_filename(file.filename, "upload.hbzf")
        in_path = Path(tmp) / safe_name
        # Strip .hbzf suffix for output name
        out_name = in_path.stem if in_path.suffix == ".hbzf" else in_path.name + ".dec"
        out_path = Path(tmp) / out_name

        content = await file.read()
        if len(content) > _MAX_UPLOAD_BYTES:
            raise HTTPException(
                status_code=413,
                detail=f"File too large (max {_MAX_UPLOAD_BYTES // (1024 * 1024)} MiB)",
            )
        in_path.write_bytes(content)

        try:
            hbz.decrypt_file(
                str(in_path),
                str(out_path),
                passphrase=passphrase.encode("utf-8"),
            )
        except Exception as e:
            raise HTTPException(status_code=400, detail=str(e)) from e

        decrypted = out_path.read_bytes()

        _audit_safe(
            hbz.audit_log_file_decrypted,
            "WEB:FILE",
            safe_name,
            len(decrypted),
            "source=web, endpoint=/api/decrypt/file",
        )

    def _iter():
        yield decrypted

    return StreamingResponse(
        _iter(),
        media_type="application/octet-stream",
        headers={
            "Content-Disposition": f'attachment; filename="{_sanitize_filename(out_name, "decrypted")}"',
            "Content-Length": str(len(decrypted)),
        },
    )


# ---------------------------------------------------------------------------
# Audit log
# ---------------------------------------------------------------------------


class AuditEntryOut(BaseModel):
    timestamp: str
    operation: str
    prev_hash: str | None
    entry_hash: str
    note: str | None


class AuditVerifyResponse(BaseModel):
    valid: bool


@router.get("/audit/recent", response_model=list[AuditEntryOut])
def audit_recent(limit: int = 50):
    """Return the most recent audit log entries."""
    try:
        return [
            AuditEntryOut(
                timestamp=e.timestamp,
                operation=e.operation,
                prev_hash=e.prev_hash,
                entry_hash=e.entry_hash,
                note=e.note,
            )
            for e in AuditService.recent_entries(limit)
        ]
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e)) from e


@router.get("/audit/verify", response_model=AuditVerifyResponse)
def audit_verify():
    """Verify audit log hash-chain integrity."""
    try:
        return AuditVerifyResponse(valid=AuditService.verify_integrity())
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e)) from e


@router.get("/audit/count")
def audit_count():
    """Return total number of audit entries."""
    try:
        return {"count": AuditService.entry_count()}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e)) from e


@router.post("/audit/export")
def audit_export(destination: str):
    """Export the audit log to a given path on the server."""
    dest = _require_home_path(destination, "destination")
    try:
        exported = AuditService.export(dest)
        return {"status": "exported", "destination": str(exported)}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e)) from e


# ---------------------------------------------------------------------------
# Backup & Restore
# ---------------------------------------------------------------------------


class BackupRequest(BaseModel):
    output_path: str
    passphrase: str
    label: str | None = None


class BackupManifestOut(BaseModel):
    created_at: str
    private_key_count: int
    public_key_count: int
    contact_count: int
    version: int
    label: str | None
    integrity_hash: str


class RestoreRequest(BaseModel):
    backup_path: str
    passphrase: str


@router.post("/backup/create", response_model=BackupManifestOut)
def create_backup(req: BackupRequest):
    """Create an encrypted backup of the keyring."""
    out = _require_home_path(req.output_path, "output_path")
    try:
        manifest = BackupService.create_backup(out, req.passphrase, req.label)
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
        raise HTTPException(status_code=400, detail=str(e)) from e


@router.post("/backup/verify", response_model=BackupManifestOut)
def verify_backup(req: RestoreRequest):
    """Verify a backup file without restoring it."""
    bpath = _require_home_path(req.backup_path, "backup_path")
    try:
        manifest = BackupService.verify_backup(bpath, req.passphrase)
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
        raise HTTPException(status_code=400, detail=str(e)) from e


@router.post("/backup/restore", response_model=BackupManifestOut)
def restore_backup(req: RestoreRequest):
    """Restore a backup, importing keys and contacts."""
    bpath = _require_home_path(req.backup_path, "backup_path")
    try:
        manifest = BackupService.restore_backup(bpath, req.passphrase)
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
        raise HTTPException(status_code=400, detail=str(e)) from e


# ---------------------------------------------------------------------------
# Config — shared config service
# ---------------------------------------------------------------------------


@router.get("/config")
def get_config():
    """Return all configuration settings."""
    try:
        return ConfigService.load()
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e)) from e


@router.get("/config/{key}")
def get_config_key(key: str):
    """Return a single configuration value."""
    try:
        return {"key": key, "value": ConfigService.get_value(key)}
    except KeyError:
        raise HTTPException(status_code=404, detail=f"Unknown config key: {key}") from None
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e)) from e


class ConfigUpdateRequest(BaseModel):
    value: object


@router.put("/config/{key}")
def set_config_key(key: str, req: ConfigUpdateRequest):
    """Set a configuration value."""
    try:
        value = ConfigService.set_value(key, req.value)
        return {"key": key, "value": value}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e)) from e


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
        raise HTTPException(status_code=400, detail=str(e)) from e


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
        raise HTTPException(status_code=400, detail=str(e)) from e


class ShamirCombineRequest(BaseModel):
    shares: list[str]


@router.post("/shamir/combine")
def shamir_combine(req: ShamirCombineRequest):
    """Combine Shamir shares to recover the secret."""
    try:
        secret = hbz.shamir_combine(req.shares)
        return {"secret_b64": base64.b64encode(secret).decode()}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e)) from e


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
        raise HTTPException(status_code=400, detail=str(e)) from e


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
        raise HTTPException(status_code=400, detail=str(e)) from e
