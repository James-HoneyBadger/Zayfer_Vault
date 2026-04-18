"""Helpers for the GUI's secure messaging workflow.

These helpers package short messages into a shareable JSON envelope using the
existing HBZF encryption format. The recipient's stored RSA or X25519 public
key is used for encryption, and the sender may optionally attach a signature.
"""

from __future__ import annotations

import base64
import json
from dataclasses import dataclass
from datetime import datetime, timezone

import hb_zayfer as hbz

_MESSAGE_FORMAT = "hbz-message"
_MESSAGE_VERSION = 1


@dataclass(slots=True)
class MessageIdentity:
    """A key that can be used in the messaging UI."""

    fingerprint: str
    label: str
    algorithm: str
    has_private: bool
    has_public: bool


@dataclass(slots=True)
class MessageDecryptResult:
    """Result returned after decrypting a message package."""

    plaintext: str
    recipient_fingerprint: str
    sender_fingerprint: str | None = None
    signature_valid: bool | None = None


def _normalize_algorithm(algorithm: str | None) -> str:
    value = (algorithm or "").strip().lower().replace("-", "").replace("_", "")
    if value.startswith("rsa"):
        return "rsa"
    if value == "x25519":
        return "x25519"
    if value == "ed25519":
        return "ed25519"
    if value in {"pgp", "openpgp"}:
        return "pgp"
    return value


def _display_label(meta) -> str:
    return f"{meta.label} ({meta.algorithm}) [{meta.fingerprint[:12]}…]"


def list_messaging_keys() -> dict[str, list[MessageIdentity]]:
    """Return keys grouped by how the messaging UI can use them."""
    ks = hbz.KeyStore()
    recipients: list[MessageIdentity] = []
    decryptors: list[MessageIdentity] = []
    signers: list[MessageIdentity] = []

    for meta in ks.list_keys():
        algo = _normalize_algorithm(meta.algorithm)
        ident = MessageIdentity(
            fingerprint=meta.fingerprint,
            label=_display_label(meta),
            algorithm=algo,
            has_private=meta.has_private,
            has_public=meta.has_public,
        )
        if ident.has_public and algo in {"rsa", "x25519"}:
            recipients.append(ident)
        if ident.has_private and algo in {"rsa", "x25519"}:
            decryptors.append(ident)
        if ident.has_private and algo in {"rsa", "ed25519", "pgp"}:
            signers.append(ident)

    return {
        "recipients": recipients,
        "decryptors": decryptors,
        "signers": signers,
    }


def _load_signing_key(ks: hbz.KeyStore, fingerprint: str, passphrase: str) -> tuple[str, str]:
    meta = ks.get_key_metadata(fingerprint)
    if not meta or not meta.has_private:
        raise ValueError("Selected signing key is unavailable.")
    algo = _normalize_algorithm(meta.algorithm)
    if algo not in {"rsa", "ed25519", "pgp"}:
        raise ValueError("Selected key cannot be used for signing.")
    if not passphrase:
        raise ValueError("Enter the passphrase for the selected signing key.")
    private_data = ks.load_private_key(fingerprint, passphrase.encode("utf-8"))
    return algo, private_data.decode("utf-8")


def create_message_package(
    plaintext: str,
    recipient_fingerprint: str,
    sender_fingerprint: str | None = None,
    sender_passphrase: str | None = None,
    symmetric_algorithm: str = "aes",
) -> str:
    """Encrypt a short message to a stored recipient key and return a JSON package."""
    message = (plaintext or "").strip()
    if not message:
        raise ValueError("Enter a message to encrypt.")

    ks = hbz.KeyStore()
    recipient_meta = ks.get_key_metadata(recipient_fingerprint)
    if not recipient_meta or not recipient_meta.has_public:
        raise ValueError("Recipient public key not found.")

    recipient_algo = _normalize_algorithm(recipient_meta.algorithm)
    public_data = ks.load_public_key(recipient_fingerprint)
    encrypt_kwargs: dict[str, object]

    if recipient_algo == "rsa":
        encrypt_kwargs = {
            "wrapping": "rsa",
            "recipient_public_pem": public_data.decode("utf-8"),
        }
    elif recipient_algo == "x25519":
        encrypt_kwargs = {
            "wrapping": "x25519",
            "recipient_public_raw": public_data,
        }
    else:
        raise ValueError("Messaging currently supports RSA and X25519 recipient keys.")

    message_bytes = message.encode("utf-8")
    ciphertext = hbz.encrypt_data(
        message_bytes,
        algorithm=symmetric_algorithm,
        **encrypt_kwargs,
    )

    signature_b64: str | None = None
    signature_algorithm: str | None = None
    if sender_fingerprint:
        signature_algorithm, private_text = _load_signing_key(
            ks,
            sender_fingerprint,
            sender_passphrase or "",
        )
        if signature_algorithm == "ed25519":
            signature = hbz.ed25519_sign(private_text, message_bytes)
        elif signature_algorithm == "rsa":
            signature = hbz.rsa_sign(private_text, message_bytes)
        elif signature_algorithm == "pgp":
            signature = hbz.pgp_sign(message_bytes, private_text)
        else:
            raise ValueError("Unsupported signing algorithm.")
        signature_b64 = base64.b64encode(signature).decode("ascii")

    package = {
        "format": _MESSAGE_FORMAT,
        "version": _MESSAGE_VERSION,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "recipient_fingerprint": recipient_fingerprint,
        "recipient_algorithm": recipient_algo,
        "sender_fingerprint": sender_fingerprint,
        "signature_algorithm": signature_algorithm,
        "ciphertext_b64": base64.b64encode(ciphertext).decode("ascii"),
        "signature_b64": signature_b64,
    }
    return json.dumps(package, indent=2)


def decrypt_message_package(
    package_text: str,
    recipient_fingerprint: str,
    recipient_passphrase: str,
) -> MessageDecryptResult:
    """Decrypt a JSON message package using the selected recipient key."""
    if not recipient_passphrase:
        raise ValueError("Enter the passphrase for your recipient key.")

    try:
        package = json.loads(package_text)
    except json.JSONDecodeError as exc:
        raise ValueError("The message is not a valid Zayfer Vault message package.") from exc

    if package.get("format") != _MESSAGE_FORMAT:
        raise ValueError("Unsupported message format.")

    expected_recipient = package.get("recipient_fingerprint")
    if expected_recipient and expected_recipient != recipient_fingerprint:
        raise ValueError("This message was encrypted for a different recipient key.")

    ks = hbz.KeyStore()
    recipient_meta = ks.get_key_metadata(recipient_fingerprint)
    if not recipient_meta or not recipient_meta.has_private:
        raise ValueError("Recipient private key not found.")

    recipient_algo = _normalize_algorithm(recipient_meta.algorithm)
    private_data = ks.load_private_key(recipient_fingerprint, recipient_passphrase.encode("utf-8"))
    ciphertext = base64.b64decode(package["ciphertext_b64"])

    if recipient_algo == "rsa":
        plaintext_bytes = hbz.decrypt_data(ciphertext, private_pem=private_data.decode("utf-8"))
    elif recipient_algo == "x25519":
        plaintext_bytes = hbz.decrypt_data(ciphertext, secret_raw=private_data)
    else:
        raise ValueError("Selected recipient key cannot decrypt messaging packages.")

    sender_fingerprint = package.get("sender_fingerprint")
    signature_algorithm = _normalize_algorithm(package.get("signature_algorithm"))
    signature_b64 = package.get("signature_b64")
    signature_valid: bool | None = None

    if sender_fingerprint and signature_b64 and signature_algorithm:
        public_data = ks.load_public_key(sender_fingerprint)
        signature = base64.b64decode(signature_b64)

        if signature_algorithm == "ed25519":
            signature_valid = bool(
                hbz.ed25519_verify(public_data.decode("utf-8"), plaintext_bytes, signature)
            )
        elif signature_algorithm == "rsa":
            signature_valid = bool(
                hbz.rsa_verify(public_data.decode("utf-8"), plaintext_bytes, signature)
            )
        elif signature_algorithm == "pgp":
            content, signature_valid = hbz.pgp_verify(signature, public_data.decode("utf-8"))
            signature_valid = bool(signature_valid and content == plaintext_bytes)

    return MessageDecryptResult(
        plaintext=plaintext_bytes.decode("utf-8", errors="replace"),
        recipient_fingerprint=recipient_fingerprint,
        sender_fingerprint=sender_fingerprint,
        signature_valid=signature_valid,
    )
