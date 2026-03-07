"""API routes for the HB_Zayfer web interface."""

from __future__ import annotations

import base64
from typing import Optional

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

import hb_zayfer as hbz

router = APIRouter()


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
        return EncryptTextResponse(ciphertext_b64=base64.b64encode(encrypted).decode())
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.post("/decrypt/text", response_model=DecryptTextResponse)
def decrypt_text(req: DecryptTextRequest):
    try:
        data = base64.b64decode(req.ciphertext_b64)
        plaintext = hbz.decrypt_data(data, passphrase=req.passphrase.encode("utf-8"))
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
        return {"status": "created", "name": req.name}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.delete("/contacts/{name}")
def remove_contact(name: str):
    try:
        ks = hbz.KeyStore()
        ks.remove_contact(name)
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
