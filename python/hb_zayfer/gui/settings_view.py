"""Settings view — application preferences with persistence."""

from __future__ import annotations

from pathlib import Path

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QWidget,
    QVBoxLayout,
    QHBoxLayout,
    QLabel,
    QComboBox,
    QCheckBox,
    QGroupBox,
    QSpinBox,
    QLineEdit,
    QPushButton,
    QMessageBox,
    QApplication,
)

import hb_zayfer as hbz
from hb_zayfer.gui.clipboard import set_auto_clear_timeout, get_auto_clear_timeout
from hb_zayfer.gui.theme import Theme
from hb_zayfer.gui.settings_manager import CryptoConfig


def _config_path() -> Path:
    """Return path to config.json (delegates to :class:`CryptoConfig`)."""
    return CryptoConfig.path()


def _load_config() -> dict:
    """Load persisted settings (delegates to :class:`CryptoConfig`)."""
    return CryptoConfig.instance().load()


def _save_config(cfg: dict) -> None:
    """Persist settings to config.json (delegates to :class:`CryptoConfig`)."""
    CryptoConfig.instance().save(cfg)


class SettingsView(QWidget):
    """Application settings and preferences."""

    def __init__(self) -> None:
        super().__init__()
        self._setup_ui()
        self._load_persisted()

    def _setup_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.setContentsMargins(16, 12, 16, 12)
        layout.setSpacing(12)

        appearance_box = QGroupBox("Appearance")
        appearance_layout = QVBoxLayout(appearance_box)

        dark_mode_row = QHBoxLayout()
        self.dark_mode_check = QCheckBox("Dark mode")
        self.dark_mode_check.stateChanged.connect(self._toggle_dark_mode)
        dark_mode_row.addWidget(self.dark_mode_check)
        dark_mode_row.addStretch()
        appearance_layout.addLayout(dark_mode_row)

        layout.addWidget(appearance_box)

        crypto_box = QGroupBox("Default Encryption Settings")
        crypto_layout = QVBoxLayout(crypto_box)

        algo_row = QHBoxLayout()
        algo_row.addWidget(QLabel("Default cipher:"))
        self.algo_combo = QComboBox()
        self.algo_combo.addItems(["AES-256-GCM", "ChaCha20-Poly1305"])
        algo_row.addWidget(self.algo_combo)
        algo_row.addStretch()
        crypto_layout.addLayout(algo_row)

        kdf_row = QHBoxLayout()
        kdf_row.addWidget(QLabel("KDF:"))
        self.kdf_combo = QComboBox()
        self.kdf_combo.addItems(["Argon2id", "scrypt"])
        kdf_row.addWidget(self.kdf_combo)
        kdf_row.addStretch()
        crypto_layout.addLayout(kdf_row)

        mem_row = QHBoxLayout()
        mem_row.addWidget(QLabel("Argon2 memory (MiB):"))
        self.mem_spin = QSpinBox()
        self.mem_spin.setRange(16, 4096)
        self.mem_spin.setValue(64)
        mem_row.addWidget(self.mem_spin)
        mem_row.addStretch()
        crypto_layout.addLayout(mem_row)

        iter_row = QHBoxLayout()
        iter_row.addWidget(QLabel("Argon2 iterations:"))
        self.iter_spin = QSpinBox()
        self.iter_spin.setRange(1, 100)
        self.iter_spin.setValue(3)
        iter_row.addWidget(self.iter_spin)
        iter_row.addStretch()
        crypto_layout.addLayout(iter_row)

        # Scrypt parameters
        scrypt_logn_row = QHBoxLayout()
        scrypt_logn_row.addWidget(QLabel("scrypt log₂(N):"))
        self.scrypt_logn_spin = QSpinBox()
        self.scrypt_logn_spin.setRange(10, 22)
        self.scrypt_logn_spin.setValue(15)
        self.scrypt_logn_spin.setToolTip("CPU/memory cost parameter (2^N). Higher = more secure but slower.")
        scrypt_logn_row.addWidget(self.scrypt_logn_spin)
        scrypt_logn_row.addStretch()
        crypto_layout.addLayout(scrypt_logn_row)

        scrypt_r_row = QHBoxLayout()
        scrypt_r_row.addWidget(QLabel("scrypt r:"))
        self.scrypt_r_spin = QSpinBox()
        self.scrypt_r_spin.setRange(1, 32)
        self.scrypt_r_spin.setValue(8)
        self.scrypt_r_spin.setToolTip("Block size parameter.")
        scrypt_r_row.addWidget(self.scrypt_r_spin)
        scrypt_r_row.addStretch()
        crypto_layout.addLayout(scrypt_r_row)

        scrypt_p_row = QHBoxLayout()
        scrypt_p_row.addWidget(QLabel("scrypt p:"))
        self.scrypt_p_spin = QSpinBox()
        self.scrypt_p_spin.setRange(1, 16)
        self.scrypt_p_spin.setValue(1)
        self.scrypt_p_spin.setToolTip("Parallelism parameter.")
        scrypt_p_row.addWidget(self.scrypt_p_spin)
        scrypt_p_row.addStretch()
        crypto_layout.addLayout(scrypt_p_row)

        # Connect KDF combo to toggle parameter visibility
        self.kdf_combo.currentIndexChanged.connect(self._on_kdf_changed)

        # Store references for toggling
        self._argon2_rows = [mem_row, iter_row]
        self._scrypt_rows = [scrypt_logn_row, scrypt_r_row, scrypt_p_row]

        layout.addWidget(crypto_box)

        # -- Security Settings --
        security_box = QGroupBox("Security")
        security_layout = QVBoxLayout(security_box)

        clip_row = QHBoxLayout()
        clip_row.addWidget(QLabel("Clipboard auto-clear (seconds):"))
        self.clip_spin = QSpinBox()
        self.clip_spin.setRange(0, 600)
        self.clip_spin.setValue(30)
        self.clip_spin.setSpecialValueText("Disabled")
        self.clip_spin.setToolTip(
            "Automatically clear the clipboard after this many seconds "
            "when sensitive data is copied. Set to 0 to disable."
        )
        clip_row.addWidget(self.clip_spin)
        clip_row.addStretch()
        security_layout.addLayout(clip_row)

        layout.addWidget(security_box)

        store_box = QGroupBox("Key Store")
        store_layout = QVBoxLayout(store_box)

        path_row = QHBoxLayout()
        path_row.addWidget(QLabel("Path:"))
        self.path_input = QLineEdit()
        try:
            ks = hbz.KeyStore()
            self.path_input.setText(ks.base_path)
        except Exception:
            self.path_input.setText("~/.hb_zayfer/")
        self.path_input.setReadOnly(True)
        path_row.addWidget(self.path_input, 1)
        store_layout.addLayout(path_row)

        layout.addWidget(store_box)

        info_box = QGroupBox("About")
        info_layout = QVBoxLayout(info_box)
        info_layout.addWidget(QLabel(f"HB_Zayfer version: {hbz.version()}"))
        info_layout.addWidget(QLabel("Crypto backend: Rust (RustCrypto + Sequoia-OpenPGP)"))
        info_layout.addWidget(QLabel("GUI toolkit: PySide6 (Qt 6)"))
        info_layout.addWidget(QLabel("License: MIT"))
        layout.addWidget(info_box)

        btn_row = QHBoxLayout()
        save_btn = QPushButton("Save Settings")
        save_btn.clicked.connect(self._on_save)
        btn_row.addWidget(save_btn)

        reset_btn = QPushButton("Reset to Defaults")
        reset_btn.clicked.connect(self._on_reset)
        btn_row.addWidget(reset_btn)

        btn_row.addStretch()
        layout.addLayout(btn_row)

        layout.addStretch()

    def _load_persisted(self) -> None:
        """Load saved settings into the UI widgets."""
        cfg = _load_config()

        self.dark_mode_check.setChecked(cfg.get("dark_mode", True))

        idx = self.algo_combo.findText(cfg.get("cipher", "AES-256-GCM"))
        if idx >= 0:
            self.algo_combo.setCurrentIndex(idx)

        idx = self.kdf_combo.findText(cfg.get("kdf", "Argon2id"))
        if idx >= 0:
            self.kdf_combo.setCurrentIndex(idx)

        self.mem_spin.setValue(cfg.get("argon2_memory_mib", 64))
        self.iter_spin.setValue(cfg.get("argon2_iterations", 3))

        self.scrypt_logn_spin.setValue(cfg.get("scrypt_log_n", 15))
        self.scrypt_r_spin.setValue(cfg.get("scrypt_r", 8))
        self.scrypt_p_spin.setValue(cfg.get("scrypt_p", 1))

        # Show/hide KDF parameter rows based on current selection
        self._on_kdf_changed(self.kdf_combo.currentIndex())

        clip_sec = cfg.get("clipboard_auto_clear", 30)
        self.clip_spin.setValue(clip_sec)
        set_auto_clear_timeout(clip_sec)

    def _current_config(self) -> dict:
        """Gather current widget values into a config dict."""
        return {
            "cipher": self.algo_combo.currentText(),
            "kdf": self.kdf_combo.currentText(),
            "argon2_memory_mib": self.mem_spin.value(),
            "argon2_iterations": self.iter_spin.value(),
            "scrypt_log_n": self.scrypt_logn_spin.value(),
            "scrypt_r": self.scrypt_r_spin.value(),
            "scrypt_p": self.scrypt_p_spin.value(),
            "dark_mode": self.dark_mode_check.isChecked(),
            "clipboard_auto_clear": self.clip_spin.value(),
        }

    def _toggle_dark_mode(self, state: int) -> None:
        """Toggle between light and dark themes."""
        app = QApplication.instance()
        if app is None:
            return
        if state == Qt.CheckState.Checked.value:
            Theme.apply_dark_theme(app)
        else:
            Theme.apply_light_theme(app)

    def _on_kdf_changed(self, index: int) -> None:
        """Show/hide KDF-specific parameter rows."""
        is_argon2 = index == 0  # Argon2id
        is_scrypt = index == 1  # scrypt
        for layout in self._argon2_rows:
            for i in range(layout.count()):
                w = layout.itemAt(i).widget()
                if w:
                    w.setVisible(is_argon2)
        for layout in self._scrypt_rows:
            for i in range(layout.count()):
                w = layout.itemAt(i).widget()
                if w:
                    w.setVisible(is_scrypt)

    def _on_save(self) -> None:
        try:
            cfg = self._current_config()
            _save_config(cfg)
            set_auto_clear_timeout(cfg["clipboard_auto_clear"])
            QMessageBox.information(self, "Settings", "Settings saved successfully.")
        except Exception as exc:
            QMessageBox.warning(self, "Error", f"Failed to save settings:\n{exc}")

    def _on_reset(self) -> None:
        self.dark_mode_check.setChecked(True)
        self.algo_combo.setCurrentIndex(0)
        self.kdf_combo.setCurrentIndex(0)
        self.mem_spin.setValue(64)
        self.iter_spin.setValue(3)
        self.scrypt_logn_spin.setValue(15)
        self.scrypt_r_spin.setValue(8)
        self.scrypt_p_spin.setValue(1)
        self.clip_spin.setValue(30)
        set_auto_clear_timeout(30)

        try:
            _save_config(self._current_config())
        except Exception:
            pass

        QMessageBox.information(self, "Settings", "Settings reset to defaults.")
