"""Best-effort audit helpers for GUI actions."""

from __future__ import annotations

import contextlib

import hb_zayfer as hbz


def audit_safe(fn, *args, **kwargs) -> None:
    """Call an audit function without raising to UI callers."""
    with contextlib.suppress(Exception):
        fn(*args, **kwargs)


def log_key_generated(algorithm: str, fingerprint: str, view: str = "keygen") -> None:
    audit_safe(hbz.audit_log_key_generated, algorithm, fingerprint, f"source=gui, view={view}")


def log_file_encrypted(
    algorithm: str, filename: str, size_bytes: int | None = None, view: str = "encrypt"
) -> None:
    audit_safe(
        hbz.audit_log_file_encrypted, algorithm, filename, size_bytes, f"source=gui, view={view}"
    )


def log_file_decrypted(
    algorithm: str, filename: str, size_bytes: int | None = None, view: str = "decrypt"
) -> None:
    audit_safe(
        hbz.audit_log_file_decrypted, algorithm, filename, size_bytes, f"source=gui, view={view}"
    )


def log_contact_added(name: str, view: str = "contacts") -> None:
    audit_safe(hbz.audit_log_contact_added, name, f"source=gui, view={view}")


def log_contact_deleted(name: str, view: str = "contacts") -> None:
    audit_safe(hbz.audit_log_contact_deleted, name, f"source=gui, view={view}")


def log_key_deleted(fingerprint: str, view: str = "keyring") -> None:
    audit_safe(hbz.audit_log_key_deleted, fingerprint, f"source=gui, view={view}")
