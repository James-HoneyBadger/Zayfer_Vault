"""Settings persistence manager for the application."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any


class SettingsManager:
    """Manages application settings persistence."""
    
    def __init__(self, config_dir: Path):
        self.config_dir = config_dir
        self.settings_file = config_dir / "gui_settings.json"
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
