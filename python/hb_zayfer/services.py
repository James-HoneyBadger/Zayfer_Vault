"""Shared application service layer for GUI, web, and other adapters.

This module centralizes high-level workflows so interface code stays thin and
consistent. It is intentionally Python-side orchestration built on top of the
native Rust-backed API exposed by :mod:`hb_zayfer`.
"""

from __future__ import annotations

import base64
import contextlib
import json
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import hb_zayfer as hbz


def _audit_safe(fn, *args, **kwargs) -> None:
    """Best-effort audit logging without surfacing secondary failures."""
    with contextlib.suppress(Exception):
        fn(*args, **kwargs)


@dataclass(frozen=True)
class AppPaths:
    """Resolved filesystem locations for user data and configuration."""

    user_home: Path
    home_dir: Path
    config_dir: Path

    @classmethod
    def current(cls) -> AppPaths:
        user_home = Path.home().expanduser().resolve()
        raw_app_home = os.environ.get("HB_ZAYFER_HOME")
        if raw_app_home:
            app_home = Path(raw_app_home).expanduser().resolve()
        else:
            app_home = user_home / ".hb_zayfer"
        return cls(user_home=user_home, home_dir=app_home, config_dir=app_home)

    def resolve_user_path(self, raw_path: str, field_name: str = "path") -> Path:
        """Resolve a user-supplied path and ensure it stays under the real home directory."""
        try:
            resolved = Path(raw_path).expanduser().resolve()
        except Exception as exc:
            raise ValueError(f"Invalid {field_name}: {exc}") from exc

        if not resolved.is_relative_to(self.user_home):
            raise ValueError(f"{field_name} must be within user's home directory")
        return resolved


@dataclass(frozen=True)
class AppInfo:
    """Small metadata object shared by desktop and web entry points."""

    brand_name: str
    version: str
    package_name: str = "hb_zayfer"
    description: str = "Encryption, secure messaging, and key management suite"

    @property
    def window_title(self) -> str:
        return f"{self.brand_name} v{self.version}"

    @property
    def api_title(self) -> str:
        return self.brand_name

    @classmethod
    def current(cls) -> AppInfo:
        return cls(brand_name="Zayfer Vault", version=hbz.version())


@dataclass(frozen=True)
class KeyGenerationResult:
    """Result returned by the shared key-generation workflow."""

    fingerprint: str
    algorithm: str
    label: str

    def to_display_text(self) -> str:
        return (
            f"Algorithm: {self.algorithm.upper()}\n"
            f"Label: {self.label}\n"
            f"Fingerprint: {self.fingerprint}"
        )


@dataclass(frozen=True)
class WorkspaceSummary:
    """Basic workspace counts used by dashboards and overview screens."""

    key_count: int
    contact_count: int
    audit_count: int

    @classmethod
    def collect(cls) -> WorkspaceSummary:
        key_count = 0
        contact_count = 0
        audit_count = 0

        with contextlib.suppress(Exception):
            ks = hbz.KeyStore()
            key_count = len(ks.list_keys())
            contact_count = len(ks.list_contacts())

        with contextlib.suppress(Exception):
            audit_count = hbz.AuditLogger().entry_count()

        return cls(
            key_count=key_count,
            contact_count=contact_count,
            audit_count=audit_count,
        )


class KeyService:
    """Shared high-level key and contact management operations."""

    @staticmethod
    def _normalize_algorithm(algorithm: str) -> str:
        value = algorithm.strip().lower().replace("-", "").replace("/", "")
        mapping = {
            "rsa2048": "rsa2048",
            "rsa4096": "rsa4096",
            "ed25519": "ed25519",
            "x25519": "x25519",
            "pgp": "pgp",
            "gpg": "pgp",
            "pgpgpg": "pgp",
        }
        normalized = mapping.get(value)
        if not normalized:
            raise ValueError(f"Unknown algorithm: {algorithm}")
        return normalized

    @staticmethod
    def keystore():
        return hbz.KeyStore()

    @classmethod
    def generate_key(
        cls,
        algorithm: str,
        label: str,
        passphrase: bytes,
        user_id: str | None = None,
    ) -> KeyGenerationResult:
        algorithm = cls._normalize_algorithm(algorithm)
        label = label.strip()
        if not label:
            raise ValueError("label is required")
        if not passphrase:
            raise ValueError("passphrase is required")

        ks = cls.keystore()

        if algorithm in ("rsa2048", "rsa4096"):
            bits = 2048 if algorithm == "rsa2048" else 4096
            priv_pem, pub_pem = hbz.rsa_generate(bits)
            fingerprint = hbz.rsa_fingerprint(pub_pem)
            ks.store_private_key(fingerprint, priv_pem.encode(), passphrase, algorithm, label)
            ks.store_public_key(fingerprint, pub_pem.encode(), algorithm, label)
        elif algorithm == "ed25519":
            secret_key, verify_key = hbz.ed25519_generate()
            fingerprint = hbz.ed25519_fingerprint(verify_key)
            ks.store_private_key(fingerprint, secret_key.encode(), passphrase, algorithm, label)
            ks.store_public_key(fingerprint, verify_key.encode(), algorithm, label)
        elif algorithm == "x25519":
            x25519_secret, x25519_public = hbz.x25519_generate()
            fingerprint = hbz.x25519_fingerprint(x25519_public)
            ks.store_private_key(fingerprint, x25519_secret, passphrase, algorithm, label)
            ks.store_public_key(fingerprint, x25519_public, algorithm, label)
        else:
            resolved_user_id = (user_id or label).strip()
            if not resolved_user_id or len(resolved_user_id) > 256:
                raise ValueError("PGP user_id must be 1–256 characters")
            pgp_public, pgp_secret = hbz.pgp_generate(resolved_user_id)
            fingerprint = hbz.pgp_fingerprint(pgp_public)
            ks.store_private_key(fingerprint, pgp_secret.encode(), passphrase, algorithm, label)
            ks.store_public_key(fingerprint, pgp_public.encode(), algorithm, label)

        _audit_safe(hbz.audit_log_key_generated, algorithm.upper(), fingerprint, "source=service")
        return KeyGenerationResult(
            fingerprint=fingerprint,
            algorithm=algorithm,
            label=label,
        )

    @classmethod
    def list_keys(cls):
        return list(cls.keystore().list_keys())

    @classmethod
    def delete_key(cls, fingerprint: str) -> None:
        cls.keystore().delete_key(fingerprint)
        _audit_safe(hbz.audit_log_key_deleted, fingerprint, "source=service")

    @classmethod
    def load_public_key(cls, fingerprint: str) -> bytes:
        return cls.keystore().load_public_key(fingerprint)

    @classmethod
    def list_contacts(cls):
        return list(cls.keystore().list_contacts())

    @classmethod
    def add_contact(cls, name: str, email: str | None = None, notes: str | None = None) -> None:
        cls.keystore().add_contact(name, email=email, notes=notes)
        _audit_safe(hbz.audit_log_contact_added, name, "source=service")

    @classmethod
    def remove_contact(cls, name: str) -> None:
        cls.keystore().remove_contact(name)
        _audit_safe(hbz.audit_log_contact_deleted, name, "source=service")

    @classmethod
    def link_key_to_contact(cls, contact_name: str, fingerprint: str) -> None:
        cls.keystore().associate_key_with_contact(contact_name, fingerprint)


class AuditService:
    """Shared audit-log operations."""

    @staticmethod
    def logger():
        return hbz.AuditLogger()

    @classmethod
    def recent_entries(cls, limit: int = 50):
        return list(cls.logger().recent_entries(limit))

    @classmethod
    def verify_integrity(cls) -> bool:
        return bool(cls.logger().verify_integrity())

    @classmethod
    def entry_count(cls) -> int:
        return int(cls.logger().entry_count())

    @classmethod
    def export(cls, destination: str | Path) -> Path:
        dest = Path(destination).expanduser().resolve()
        dest.parent.mkdir(parents=True, exist_ok=True)
        cls.logger().export(str(dest))
        return dest


class BackupService:
    """Shared backup creation, verification, and restore workflows."""

    @staticmethod
    def _passphrase_bytes(passphrase: str | bytes) -> bytes:
        return passphrase if isinstance(passphrase, bytes) else passphrase.encode("utf-8")

    @classmethod
    def create_backup(
        cls,
        output_path: str | Path,
        passphrase: str | bytes,
        label: str | None = None,
    ):
        out = Path(output_path).expanduser().resolve()
        out.parent.mkdir(parents=True, exist_ok=True)
        pw = cls._passphrase_bytes(passphrase)
        ks = KeyService.keystore()
        ks.create_backup(str(out), pw, label)
        return ks.verify_backup(str(out), pw)

    @classmethod
    def verify_backup(cls, backup_path: str | Path, passphrase: str | bytes):
        path = Path(backup_path).expanduser().resolve()
        pw = cls._passphrase_bytes(passphrase)
        return KeyService.keystore().verify_backup(str(path), pw)

    @classmethod
    def restore_backup(cls, backup_path: str | Path, passphrase: str | bytes):
        path = Path(backup_path).expanduser().resolve()
        pw = cls._passphrase_bytes(passphrase)
        return KeyService.keystore().restore_backup(str(path), pw)


_CONFIG_DEFAULTS = {
    "cipher": "AES-256-GCM",
    "kdf": "Argon2id",
    "argon2_memory_mib": 64,
    "argon2_iterations": 3,
    "dark_mode": True,
    "clipboard_auto_clear": 30,
}


class ConfigService:
    """Shared configuration persistence for non-GUI adapters."""

    @classmethod
    def config_path(cls) -> Path:
        return AppPaths.current().config_dir / "config.json"

    @classmethod
    def load(cls) -> dict[str, Any]:
        path = cls.config_path()
        config = dict(_CONFIG_DEFAULTS)
        if path.exists():
            try:
                with open(path, encoding="utf-8") as handle:
                    config.update(json.load(handle))
            except Exception:
                pass
        return config

    @classmethod
    def save(cls, config: dict[str, Any]) -> None:
        path = cls.config_path()
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_suffix(".tmp")
        with open(tmp, "w", encoding="utf-8") as handle:
            json.dump(config, handle, indent=2)
        tmp.rename(path)

    @classmethod
    def get_value(cls, key: str):
        config = cls.load()
        if key not in config:
            raise KeyError(key)
        return config[key]

    @classmethod
    def set_value(cls, key: str, value: Any) -> Any:
        config = cls.load()
        config[key] = value
        cls.save(config)
        return value


class CryptoService:
    """Shared text-encryption helpers for web and future UI flows."""

    @staticmethod
    def encrypt_text(plaintext: str, passphrase: str, algorithm: str = "aes") -> str:
        if not passphrase:
            raise ValueError("passphrase is required")
        encrypted = hbz.encrypt_data(
            plaintext.encode("utf-8"),
            algorithm=algorithm,
            wrapping="password",
            passphrase=passphrase.encode("utf-8"),
        )
        _audit_safe(
            hbz.audit_log_file_encrypted,
            algorithm.upper(),
            "service:text",
            len(plaintext.encode("utf-8")),
            "source=service",
        )
        return base64.b64encode(encrypted).decode()

    @staticmethod
    def decrypt_text(ciphertext_b64: str, passphrase: str) -> str:
        data = base64.b64decode(ciphertext_b64)
        plaintext = hbz.decrypt_data(data, passphrase=passphrase.encode("utf-8"))
        _audit_safe(
            hbz.audit_log_file_decrypted,
            "SERVICE:TEXT",
            "service:text",
            len(plaintext),
            "source=service",
        )
        return plaintext.decode("utf-8", errors="replace")


class SignatureService:
    """Shared message signing and verification helpers."""

    @staticmethod
    def _normalize_algorithm(algorithm: str) -> str:
        value = algorithm.strip().lower().replace("-", "").replace("/", "")
        if value in {"ed25519"}:
            return "ed25519"
        if value in {"rsa", "rsa2048", "rsa4096"}:
            return "rsa"
        if value in {"pgp", "gpg"}:
            return "pgp"
        raise ValueError(f"Unknown algorithm: {algorithm}")

    @classmethod
    def sign_message(
        cls,
        message_b64: str,
        fingerprint: str,
        passphrase: str,
        algorithm: str = "ed25519",
    ) -> str:
        algo = cls._normalize_algorithm(algorithm)
        message = base64.b64decode(message_b64)
        priv_data = KeyService.keystore().load_private_key(fingerprint, passphrase.encode("utf-8"))

        if algo == "ed25519":
            signature = hbz.ed25519_sign(priv_data.decode(), message)
        elif algo == "rsa":
            signature = hbz.rsa_sign(priv_data.decode(), message)
        else:
            signature = hbz.pgp_sign(message, priv_data.decode())

        _audit_safe(hbz.audit_log_data_signed, algo.upper(), fingerprint, "source=service")
        return base64.b64encode(signature).decode()

    @classmethod
    def verify_message(
        cls,
        message_b64: str,
        signature_b64: str,
        fingerprint: str,
        algorithm: str = "ed25519",
    ) -> bool:
        algo = cls._normalize_algorithm(algorithm)
        message = base64.b64decode(message_b64)
        signature = base64.b64decode(signature_b64)
        pub_data = KeyService.keystore().load_public_key(fingerprint)

        if algo == "ed25519":
            valid = hbz.ed25519_verify(pub_data.decode(), message, signature)
        elif algo == "rsa":
            valid = hbz.rsa_verify(pub_data.decode(), message, signature)
        else:
            _, valid = hbz.pgp_verify(signature, pub_data.decode())

        _audit_safe(hbz.audit_log_signature_verified, algo.upper(), fingerprint, bool(valid))
        return bool(valid)
