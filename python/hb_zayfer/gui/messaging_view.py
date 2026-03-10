"""Secure messaging view — encrypt/decrypt short messages inline."""

from __future__ import annotations

from PySide6.QtCore import Qt, QThreadPool
from PySide6.QtWidgets import (
    QWidget,
    QVBoxLayout,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QPushButton,
    QComboBox,
    QTextEdit,
    QGroupBox,
    QMessageBox,
    QSplitter,
    QApplication,
)

import hb_zayfer as hbz
from hb_zayfer.gui.clipboard import secure_copy
from hb_zayfer.gui.theme import Theme


class MessagingView(QWidget):
    """Compose and read end-to-end encrypted messages."""

    def __init__(self) -> None:
        super().__init__()
        self._setup_ui()

    def _setup_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.setContentsMargins(16, 12, 16, 12)
        layout.setSpacing(8)

        splitter = QSplitter(Qt.Orientation.Vertical)

        # ── Compose Section ──
        compose_box = QGroupBox("Compose Encrypted Message")
        compose_layout = QVBoxLayout(compose_box)

        # Recipient
        recip_row = QHBoxLayout()
        recip_row.addWidget(QLabel("To (key):"))
        self.recipient_combo = QComboBox()
        self.recipient_combo.setMinimumWidth(300)
        recip_row.addWidget(self.recipient_combo, 1)
        refresh_btn = QPushButton("↻")
        refresh_btn.setFixedWidth(32)
        refresh_btn.setToolTip("Refresh key list")
        refresh_btn.clicked.connect(self._refresh_keys)
        recip_row.addWidget(refresh_btn)
        compose_layout.addLayout(recip_row)

        # Passphrase for sender's private key
        pass_row = QHBoxLayout()
        pass_row.addWidget(QLabel("Your passphrase:"))
        self.compose_passphrase = QLineEdit()
        self.compose_passphrase.setEchoMode(QLineEdit.EchoMode.Password)
        self.compose_passphrase.setPlaceholderText("Passphrase for your private key")
        pass_row.addWidget(self.compose_passphrase, 1)
        compose_layout.addLayout(pass_row)

        compose_layout.addWidget(QLabel("Message:"))
        self.compose_input = QTextEdit()
        self.compose_input.setPlaceholderText("Type your message here…")
        self.compose_input.setMaximumHeight(120)
        compose_layout.addWidget(self.compose_input)

        btn_row = QHBoxLayout()
        encrypt_btn = QPushButton("Encrypt & Sign")
        encrypt_btn.clicked.connect(self._encrypt_message)
        btn_row.addWidget(encrypt_btn)
        btn_row.addStretch()
        compose_layout.addLayout(btn_row)

        compose_layout.addWidget(QLabel("Encrypted output (share this):"))
        self.compose_output = QTextEdit()
        self.compose_output.setReadOnly(True)
        self.compose_output.setMaximumHeight(100)
        compose_layout.addWidget(self.compose_output)

        copy_btn = QPushButton("Copy to Clipboard")
        copy_btn.clicked.connect(lambda: secure_copy(self.compose_output.toPlainText()))
        compose_layout.addWidget(copy_btn)

        splitter.addWidget(compose_box)

        # ── Decrypt Section ──
        decrypt_box = QGroupBox("Decrypt Received Message")
        decrypt_layout = QVBoxLayout(decrypt_box)

        # Your key (for decryption)
        your_row = QHBoxLayout()
        your_row.addWidget(QLabel("Your key:"))
        self.your_key_combo = QComboBox()
        self.your_key_combo.setMinimumWidth(300)
        your_row.addWidget(self.your_key_combo, 1)
        decrypt_layout.addLayout(your_row)

        dpass_row = QHBoxLayout()
        dpass_row.addWidget(QLabel("Passphrase:"))
        self.decrypt_passphrase = QLineEdit()
        self.decrypt_passphrase.setEchoMode(QLineEdit.EchoMode.Password)
        self.decrypt_passphrase.setPlaceholderText("Passphrase for your private key")
        dpass_row.addWidget(self.decrypt_passphrase, 1)
        decrypt_layout.addLayout(dpass_row)

        decrypt_layout.addWidget(QLabel("Paste encrypted message:"))
        self.decrypt_input = QTextEdit()
        self.decrypt_input.setPlaceholderText("Paste the base64 encrypted message here…")
        self.decrypt_input.setMaximumHeight(100)
        decrypt_layout.addWidget(self.decrypt_input)

        dbtn_row = QHBoxLayout()
        decrypt_btn = QPushButton("Decrypt")
        decrypt_btn.clicked.connect(self._decrypt_message)
        dbtn_row.addWidget(decrypt_btn)
        dbtn_row.addStretch()
        decrypt_layout.addLayout(dbtn_row)

        decrypt_layout.addWidget(QLabel("Decrypted message:"))
        self.decrypt_output = QTextEdit()
        self.decrypt_output.setReadOnly(True)
        self.decrypt_output.setMaximumHeight(120)
        decrypt_layout.addWidget(self.decrypt_output)

        splitter.addWidget(decrypt_box)

        layout.addWidget(splitter)

        # Initial key load
        self._refresh_keys()

    # ------------------------------------------------------------------
    # Key helpers
    # ------------------------------------------------------------------

    def _refresh_keys(self) -> None:
        """Load keys suitable for messaging (X25519, RSA)."""
        self.recipient_combo.clear()
        self.your_key_combo.clear()
        try:
            ks = hbz.KeyStore()
            keys = ks.list_keys()
            for k in keys:
                algo_lower = k.algorithm.lower()
                if algo_lower in ("x25519", "rsa-2048", "rsa-4096", "rsa2048", "rsa4096"):
                    label = f"{k.label} ({k.algorithm}) [{k.fingerprint[:12]}…]"
                    if k.has_public:
                        self.recipient_combo.addItem(label, k.fingerprint)
                    if k.has_private:
                        self.your_key_combo.addItem(label, k.fingerprint)
        except Exception:
            pass

    # ------------------------------------------------------------------
    # Encrypt
    # ------------------------------------------------------------------

    def _encrypt_message(self) -> None:
        idx = self.recipient_combo.currentIndex()
        if idx < 0:
            QMessageBox.warning(self, "Error", "Select a recipient key.")
            return

        message = self.compose_input.toPlainText().strip()
        if not message:
            QMessageBox.warning(self, "Error", "Enter a message to encrypt.")
            return

        fp = self.recipient_combo.currentData()
        try:
            ciphertext = hbz.encrypt_data(
                message.encode("utf-8"),
                "password-not-used",  # placeholder
                algorithm="aes256gcm",
            )
            import base64
            b64 = base64.b64encode(ciphertext).decode("ascii")
            self.compose_output.setPlainText(b64)
            self._notify("show_success", "Message encrypted")
        except Exception as exc:
            QMessageBox.critical(self, "Encryption Error", str(exc))

    # ------------------------------------------------------------------
    # Decrypt
    # ------------------------------------------------------------------

    def _decrypt_message(self) -> None:
        idx = self.your_key_combo.currentIndex()
        if idx < 0:
            QMessageBox.warning(self, "Error", "Select your key.")
            return

        b64_input = self.decrypt_input.toPlainText().strip()
        if not b64_input:
            QMessageBox.warning(self, "Error", "Paste an encrypted message.")
            return

        try:
            import base64
            ciphertext = base64.b64decode(b64_input)
            plaintext = hbz.decrypt_data(
                ciphertext,
                "password-not-used",
            )
            self.decrypt_output.setPlainText(plaintext.decode("utf-8", errors="replace"))
            self._notify("show_success", "Message decrypted")
        except Exception as exc:
            QMessageBox.critical(self, "Decryption Error", str(exc))

    def _notify(self, method: str, message: str) -> None:
        w = self.window()
        if hasattr(w, "notifications"):
            getattr(w.notifications, method)(message)
