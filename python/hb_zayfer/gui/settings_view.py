"""Settings view — application preferences."""

from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QWidget,
    QVBoxLayout,
    QHBoxLayout,
    QLabel,
    QComboBox,
    QGroupBox,
    QSpinBox,
    QLineEdit,
    QPushButton,
    QMessageBox,
)

import hb_zayfer as hbz


class SettingsView(QWidget):
    """Application settings and preferences."""

    def __init__(self) -> None:
        super().__init__()
        self._setup_ui()

    def _setup_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 20, 20, 20)

        title = QLabel("<h2>Settings</h2>")
        layout.addWidget(title)

        # Default cipher
        crypto_box = QGroupBox("Default Encryption Settings")
        crypto_layout = QVBoxLayout(crypto_box)

        algo_row = QHBoxLayout()
        algo_row.addWidget(QLabel("Default cipher:"))
        self.algo_combo = QComboBox()
        self.algo_combo.addItems(["AES-256-GCM", "ChaCha20-Poly1305"])
        algo_row.addWidget(self.algo_combo)
        algo_row.addStretch()
        crypto_layout.addLayout(algo_row)

        # KDF settings
        kdf_row = QHBoxLayout()
        kdf_row.addWidget(QLabel("KDF:"))
        self.kdf_combo = QComboBox()
        self.kdf_combo.addItems(["Argon2id", "scrypt"])
        kdf_row.addWidget(self.kdf_combo)
        kdf_row.addStretch()
        crypto_layout.addLayout(kdf_row)

        # Argon2 memory
        mem_row = QHBoxLayout()
        mem_row.addWidget(QLabel("Argon2 memory (MiB):"))
        self.mem_spin = QSpinBox()
        self.mem_spin.setRange(16, 4096)
        self.mem_spin.setValue(64)
        mem_row.addWidget(self.mem_spin)
        mem_row.addStretch()
        crypto_layout.addLayout(mem_row)

        # Argon2 iterations
        iter_row = QHBoxLayout()
        iter_row.addWidget(QLabel("Argon2 iterations:"))
        self.iter_spin = QSpinBox()
        self.iter_spin.setRange(1, 100)
        self.iter_spin.setValue(3)
        iter_row.addWidget(self.iter_spin)
        iter_row.addStretch()
        crypto_layout.addLayout(iter_row)

        layout.addWidget(crypto_box)

        # Keystore path
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

        # Info
        info_box = QGroupBox("About")
        info_layout = QVBoxLayout(info_box)
        info_layout.addWidget(QLabel(f"HB_Zayfer version: {hbz.version()}"))
        info_layout.addWidget(QLabel("Crypto backend: Rust (RustCrypto + Sequoia-OpenPGP)"))
        info_layout.addWidget(QLabel("GUI toolkit: PySide6 (Qt 6)"))
        info_layout.addWidget(QLabel("License: MIT"))
        layout.addWidget(info_box)

        layout.addStretch()
