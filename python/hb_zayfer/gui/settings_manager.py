"""Settings persistence manager for the application."""

from __future__ import annotations

import json
import threading
from pathlib import Path
from typing import Any

from hb_zayfer.services import AppPaths


class SettingsManager:
    """Manages application settings persistence."""
    
    def __init__(self, config_dir: Path | None = None):
        self.config_dir = config_dir or AppPaths.current().config_dir
        self.settings_file = self.config_dir / "gui_settings.json"
        self._lock = threading.Lock()
        self.settings: dict[str, Any] = self._load_settings()
    
    def _load_settings(self) -> dict[str, Any]:
        """Load settings from disk."""
        if self.settings_file.exists():
            try:
                with open(self.settings_file, 'r') as f:
                    return json.load(f)
            except Exception:
                pass
        return self._default_settings()
    
    def _default_settings(self) -> dict[str, Any]:
        """Return default settings."""
        return {
            "window": {
                "width": 1000,
                "height": 700,
                "x": None,
                "y": None,
                "maximized": False
            },
            "theme": "dark",
            "last_paths": {
                "encrypt_input": "",
                "encrypt_output": "",
                "decrypt_input": "",
                "decrypt_output": "",
                "key_export": "",
                "key_import": ""
            },
            "recent_files": {
                "encrypted": [],
                "decrypted": []
            },
            "preferences": {
                "default_algorithm": "ChaCha20-Poly1305",
                "default_mode": "password",
                "confirm_delete": True,
                "show_passwords": False,
                "auto_refresh": True
            },
            "table_columns": {
                "keyring": [True, True, True, True, True, True],
                "contacts": [True, True, True, True]
            }
        }
    
    def save(self) -> None:
        """Save settings to disk."""
        with self._lock:
            try:
                self.config_dir.mkdir(parents=True, exist_ok=True)
                with open(self.settings_file, 'w') as f:
                    json.dump(self.settings, f, indent=2)
            except Exception as e:
                print(f"Failed to save settings: {e}")
    
    def get(self, key: str, default: Any = None) -> Any:
        """Get a setting value by dot-notation key.
        
        Args:
            key: Setting key in dot notation (e.g., "window.width")
            default: Default value if key not found
        
        Returns:
            The setting value or default
        """
        keys = key.split('.')
        value = self.settings
        for k in keys:
            if isinstance(value, dict):
                value = value.get(k)
                if value is None:
                    return default
            else:
                return default
        return value
    
    def set(self, key: str, value: Any) -> None:
        """Set a setting value by dot-notation key.
        
        Args:
            key: Setting key in dot notation (e.g., "window.width")
            value: Value to set
        """
        keys = key.split('.')
        target = self.settings
        for k in keys[:-1]:
            if k not in target:
                target[k] = {}
            target = target[k]
        target[keys[-1]] = value
    
    def add_recent_file(self, file_type: str, path: str, max_recent: int = 10) -> None:
        """Add a file to recent files list.
        
        Args:
            file_type: Type of file ("encrypted" or "decrypted")
            path: File path
            max_recent: Maximum number of recent files to keep
        """
        recent = self.get(f"recent_files.{file_type}", [])
        if path in recent:
            recent.remove(path)
        recent.insert(0, path)
        self.set(f"recent_files.{file_type}", recent[:max_recent])
    
    def get_recent_files(self, file_type: str) -> list[str]:
        """Get recent files of a specific type.
        
        Args:
            file_type: Type of file ("encrypted" or "decrypted")
        
        Returns:
            List of recent file paths
        """
        recent = self.get(f"recent_files.{file_type}", [])
        # Filter out files that no longer exist
        return [f for f in recent if Path(f).exists()]


# ---------------------------------------------------------------------------
# CryptoConfig — single source of truth for cipher/KDF/clipboard settings
# ---------------------------------------------------------------------------

_CRYPTO_DEFAULTS: dict[str, Any] = {
    "cipher": "AES-256-GCM",
    "kdf": "Argon2id",
    "argon2_memory_mib": 64,
    "argon2_iterations": 3,
    "scrypt_log_n": 15,
    "scrypt_r": 8,
    "scrypt_p": 1,
    "dark_mode": True,
    "clipboard_auto_clear": 30,
}


class CryptoConfig:
    """Centralized accessor for the on-disk ``config.json`` used by the
    crypto operations (cipher selection, KDF parameters, clipboard timeout).

    Replaces the duplicated ``_load_config`` / ``_load_kdf_settings`` /
    ``_load_default_cipher`` helpers that previously lived in
    :mod:`hb_zayfer.gui.encrypt_view` and :mod:`hb_zayfer.gui.settings_view`.

    Reads are best-effort and never raise — callers always get sensible
    defaults if the file is missing or corrupt. Writes are atomic.
    """

    _instance: "CryptoConfig | None" = None

    def __init__(self) -> None:
        self._lock = threading.Lock()

    @classmethod
    def instance(cls) -> "CryptoConfig":
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance

    @staticmethod
    def path() -> Path:
        try:
            import hb_zayfer as hbz  # local import: avoids GUI import-cycle at module load

            return Path(hbz.KeyStore().base_path) / "config.json"
        except Exception:
            return Path.home() / ".hb_zayfer" / "config.json"

    def load(self) -> dict[str, Any]:
        cfg = dict(_CRYPTO_DEFAULTS)
        p = self.path()
        if p.exists():
            try:
                with open(p, encoding="utf-8") as f:
                    cfg.update(json.load(f))
            except Exception:
                pass
        return cfg

    def save(self, cfg: dict[str, Any]) -> None:
        with self._lock:
            p = self.path()
            p.parent.mkdir(parents=True, exist_ok=True)
            tmp = p.with_suffix(".tmp")
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump(cfg, f, indent=2)
            tmp.replace(p)

    def default_cipher(self) -> str:
        return self.load().get("cipher", "AES-256-GCM")

    def kdf_settings(self) -> dict[str, Any]:
        """Return KDF parameters in the form expected by ``hbz`` encrypt calls."""
        cfg = self.load()
        kdf_name = str(cfg.get("kdf", "Argon2id")).lower()
        if kdf_name == "scrypt":
            return {
                "kdf": "scrypt",
                "kdf_log_n": int(cfg.get("scrypt_log_n", 15)),
                "kdf_r": int(cfg.get("scrypt_r", 8)),
                "kdf_p": int(cfg.get("scrypt_p", 1)),
            }
        return {
            "kdf": "argon2id",
            "kdf_memory_kib": int(cfg.get("argon2_memory_mib", 64)) * 1024,
            "kdf_iterations": int(cfg.get("argon2_iterations", 3)),
        }
