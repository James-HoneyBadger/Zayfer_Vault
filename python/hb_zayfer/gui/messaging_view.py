"""Secure messaging view — encrypt/decrypt short messages inline."""

from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QComboBox,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPushButton,
    QSplitter,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

from hb_zayfer.gui.clipboard import secure_copy
from hb_zayfer.gui.messaging_utils import (
    create_message_package,
    decrypt_message_package,
    list_messaging_keys,
)


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

        recip_row = QHBoxLayout()
        recip_row.addWidget(QLabel("To (recipient key):"))
        self.recipient_combo = QComboBox()
        self.recipient_combo.setMinimumWidth(320)
        recip_row.addWidget(self.recipient_combo, 1)
        refresh_btn = QPushButton("↻")
        refresh_btn.setFixedWidth(32)
        refresh_btn.setToolTip("Refresh key list")
        refresh_btn.clicked.connect(self._refresh_keys)
        recip_row.addWidget(refresh_btn)
        compose_layout.addLayout(recip_row)

        sender_row = QHBoxLayout()
        sender_row.addWidget(QLabel("Sign as:"))
        self.sender_key_combo = QComboBox()
        self.sender_key_combo.setMinimumWidth(320)
        sender_row.addWidget(self.sender_key_combo, 1)
        compose_layout.addLayout(sender_row)

        pass_row = QHBoxLayout()
        pass_row.addWidget(QLabel("Signing key passphrase:"))
        self.compose_passphrase = QLineEdit()
        self.compose_passphrase.setEchoMode(QLineEdit.EchoMode.Password)
        self.compose_passphrase.setPlaceholderText("Required only when signing")
        pass_row.addWidget(self.compose_passphrase, 1)
        compose_layout.addLayout(pass_row)

        compose_layout.addWidget(QLabel("Message:"))
        self.compose_input = QTextEdit()
        self.compose_input.setPlaceholderText("Type your message here…")
        self.compose_input.setMaximumHeight(120)
        compose_layout.addWidget(self.compose_input)

        btn_row = QHBoxLayout()
        encrypt_btn = QPushButton("Encrypt Message")
        encrypt_btn.clicked.connect(self._encrypt_message)
        btn_row.addWidget(encrypt_btn)
        btn_row.addStretch()
        compose_layout.addLayout(btn_row)

        compose_layout.addWidget(QLabel("Encrypted package (share this JSON):"))
        self.compose_output = QTextEdit()
        self.compose_output.setReadOnly(True)
        self.compose_output.setMaximumHeight(130)
        self.compose_output.setPlaceholderText("The encrypted message package will appear here…")
        compose_layout.addWidget(self.compose_output)

        copy_btn = QPushButton("Copy to Clipboard")
        copy_btn.clicked.connect(lambda: secure_copy(self.compose_output.toPlainText()))
        compose_layout.addWidget(copy_btn)

        splitter.addWidget(compose_box)

        # ── Decrypt Section ──
        decrypt_box = QGroupBox("Decrypt Received Message")
        decrypt_layout = QVBoxLayout(decrypt_box)

        your_row = QHBoxLayout()
        your_row.addWidget(QLabel("Decrypt with:"))
        self.your_key_combo = QComboBox()
        self.your_key_combo.setMinimumWidth(320)
        your_row.addWidget(self.your_key_combo, 1)
        decrypt_layout.addLayout(your_row)

        dpass_row = QHBoxLayout()
        dpass_row.addWidget(QLabel("Key passphrase:"))
        self.decrypt_passphrase = QLineEdit()
        self.decrypt_passphrase.setEchoMode(QLineEdit.EchoMode.Password)
        self.decrypt_passphrase.setPlaceholderText("Passphrase for your RSA or X25519 key")
        dpass_row.addWidget(self.decrypt_passphrase, 1)
        decrypt_layout.addLayout(dpass_row)

        decrypt_layout.addWidget(QLabel("Paste encrypted package:"))
        self.decrypt_input = QTextEdit()
        self.decrypt_input.setPlaceholderText("Paste the JSON message package here…")
        self.decrypt_input.setMaximumHeight(130)
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
        self._refresh_keys()

    # ------------------------------------------------------------------
    # Key helpers
    # ------------------------------------------------------------------

    def _refresh_keys(self) -> None:
        """Load keys suitable for messaging and signing."""
        self.recipient_combo.clear()
        self.your_key_combo.clear()
        self.sender_key_combo.clear()
        self.sender_key_combo.addItem("No signature (encrypt only)", None)

        try:
            groups = list_messaging_keys()
            for ident in groups["recipients"]:
                self.recipient_combo.addItem(ident.label, ident.fingerprint)
            for ident in groups["decryptors"]:
                self.your_key_combo.addItem(ident.label, ident.fingerprint)
            for ident in groups["signers"]:
                self.sender_key_combo.addItem(ident.label, ident.fingerprint)
        except Exception:
            pass

        if self.recipient_combo.count() == 0:
            self.recipient_combo.addItem("No RSA/X25519 public keys available", None)
        if self.your_key_combo.count() == 0:
            self.your_key_combo.addItem("No RSA/X25519 private keys available", None)

    # ------------------------------------------------------------------
    # Encrypt
    # ------------------------------------------------------------------

    def _encrypt_message(self) -> None:
        fp = self.recipient_combo.currentData()
        if not fp:
            QMessageBox.warning(self, "Error", "Select a recipient key.")
            return

        message = self.compose_input.toPlainText().strip()
        if not message:
            QMessageBox.warning(self, "Error", "Enter a message to encrypt.")
            return

        sender_fp = self.sender_key_combo.currentData()
        sender_passphrase = self.compose_passphrase.text()

        try:
            package = create_message_package(
                message,
                recipient_fingerprint=fp,
                sender_fingerprint=sender_fp,
                sender_passphrase=sender_passphrase,
            )
            self.compose_output.setPlainText(package)
            if sender_fp:
                self._notify("show_success", "Message encrypted and signed")
            else:
                self._notify("show_success", "Message encrypted")
        except Exception as exc:
            QMessageBox.critical(self, "Encryption Error", str(exc))

    # ------------------------------------------------------------------
    # Decrypt
    # ------------------------------------------------------------------

    def _decrypt_message(self) -> None:
        fp = self.your_key_combo.currentData()
        if not fp:
            QMessageBox.warning(self, "Error", "Select your decryption key.")
            return

        package_text = self.decrypt_input.toPlainText().strip()
        if not package_text:
            QMessageBox.warning(self, "Error", "Paste an encrypted message package.")
            return

        try:
            result = decrypt_message_package(
                package_text,
                recipient_fingerprint=fp,
                recipient_passphrase=self.decrypt_passphrase.text(),
            )
            self.decrypt_output.setPlainText(result.plaintext)
            if result.signature_valid is True:
                self._notify("show_success", "Message decrypted — signature verified")
            elif result.signature_valid is False:
                self._notify("show_warning", "Message decrypted — signature check failed")
            else:
                self._notify("show_info", "Message decrypted")
        except Exception as exc:
            QMessageBox.critical(self, "Decryption Error", str(exc))

    def _notify(self, method: str, message: str) -> None:
        w = self.window()
        if hasattr(w, "notifications"):
            getattr(w.notifications, method)(message)
