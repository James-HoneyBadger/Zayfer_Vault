"""Sign view — sign files or messages with Ed25519, RSA, or PGP keys."""

from __future__ import annotations

from pathlib import Path

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QWidget,
    QVBoxLayout,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QPushButton,
    QComboBox,
    QFileDialog,
    QTextEdit,
    QGroupBox,
    QProgressBar,
    QMessageBox,
    QTabWidget,
    QApplication,
)

import hb_zayfer as hbz
from hb_zayfer.gui.clipboard import secure_copy
from hb_zayfer.gui.audit_utils import audit_safe


class SignView(QWidget):
    """Sign files or text with signing keys."""

    def __init__(self) -> None:
        super().__init__()
        self._setup_ui()

    def _setup_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.setContentsMargins(16, 12, 16, 12)
        layout.setSpacing(12)

        self.tabs = QTabWidget()
        self.tabs.addTab(self._build_file_tab(), "File")
        self.tabs.addTab(self._build_text_tab(), "Text")
        layout.addWidget(self.tabs, 1)

    # ------------------------------------------------------------------
    # File tab
    # ------------------------------------------------------------------

    def _build_file_tab(self) -> QWidget:
        w = QWidget()
        layout = QVBoxLayout(w)
        layout.setSpacing(10)

        # Input file
        row = QHBoxLayout()
        row.addWidget(QLabel("Input file:"))
        self.file_input = QLineEdit()
        self.file_input.setPlaceholderText("File to sign")
        row.addWidget(self.file_input, 1)
        browse_btn = QPushButton("Browse…")
        browse_btn.clicked.connect(self._browse_input_file)
        row.addWidget(browse_btn)
        layout.addLayout(row)

        # Output file
        out_row = QHBoxLayout()
        out_row.addWidget(QLabel("Signature:"))
        self.file_output = QLineEdit()
        self.file_output.setPlaceholderText("Output signature file (auto-generated if empty)")
        out_row.addWidget(self.file_output, 1)
        out_browse = QPushButton("Browse…")
        out_browse.clicked.connect(self._browse_output_file)
        out_row.addWidget(out_browse)
        layout.addLayout(out_row)

        # Key selection
        key_row = QHBoxLayout()
        key_row.addWidget(QLabel("Signing key:"))
        self.file_key_combo = QComboBox()
        self.file_key_combo.setMinimumWidth(350)
        key_row.addWidget(self.file_key_combo, 1)
        refresh_btn = QPushButton("↻")
        refresh_btn.setToolTip("Refresh key list")
        refresh_btn.setFixedWidth(30)
        refresh_btn.clicked.connect(self._refresh_keys)
        key_row.addWidget(refresh_btn)
        layout.addLayout(key_row)

        # Passphrase
        pw_row = QHBoxLayout()
        pw_row.addWidget(QLabel("Passphrase:"))
        self.file_passphrase = QLineEdit()
        self.file_passphrase.setEchoMode(QLineEdit.EchoMode.Password)
        self.file_passphrase.setPlaceholderText("Private key passphrase")
        pw_row.addWidget(self.file_passphrase, 1)
        layout.addLayout(pw_row)

        # Sign button
        self.file_sign_btn = QPushButton("Sign File")
        self.file_sign_btn.clicked.connect(self._sign_file)
        layout.addWidget(self.file_sign_btn)

        self.file_status = QLabel("")
        layout.addWidget(self.file_status)
        layout.addStretch()

        self._refresh_keys()
        return w

    # ------------------------------------------------------------------
    # Text tab
    # ------------------------------------------------------------------

    def _build_text_tab(self) -> QWidget:
        w = QWidget()
        layout = QVBoxLayout(w)
        layout.setSpacing(10)

        layout.addWidget(QLabel("Message to sign:"))
        self.text_input = QTextEdit()
        self.text_input.setPlaceholderText("Enter or paste the message to sign…")
        layout.addWidget(self.text_input, 1)

        # Key selection
        key_row = QHBoxLayout()
        key_row.addWidget(QLabel("Signing key:"))
        self.text_key_combo = QComboBox()
        self.text_key_combo.setMinimumWidth(350)
        key_row.addWidget(self.text_key_combo, 1)
        layout.addLayout(key_row)

        # Passphrase
        pw_row = QHBoxLayout()
        pw_row.addWidget(QLabel("Passphrase:"))
        self.text_passphrase = QLineEdit()
        self.text_passphrase.setEchoMode(QLineEdit.EchoMode.Password)
        self.text_passphrase.setPlaceholderText("Private key passphrase")
        pw_row.addWidget(self.text_passphrase, 1)
        layout.addLayout(pw_row)

        self.text_sign_btn = QPushButton("Sign Message")
        self.text_sign_btn.clicked.connect(self._sign_text)
        layout.addWidget(self.text_sign_btn)

        layout.addWidget(QLabel("Signature (base64):"))
        self.text_output = QTextEdit()
        self.text_output.setReadOnly(True)
        self.text_output.setMaximumHeight(100)
        layout.addWidget(self.text_output)

        copy_btn = QPushButton("Copy Signature")
        copy_btn.clicked.connect(lambda: secure_copy(self.text_output.toPlainText()))
        layout.addWidget(copy_btn)

        return w

    # ------------------------------------------------------------------
    # Key helpers
    # ------------------------------------------------------------------

    def _refresh_keys(self) -> None:
        """Populate key combos with signing-capable keys."""
        try:
            ks = hbz.KeyStore()
            keys = [k for k in ks.list_keys() if k.has_private and k.algorithm.lower() in ("ed25519", "rsa2048", "rsa4096", "pgp")]
            for combo in (self.file_key_combo, self.text_key_combo):
                combo.clear()
                for k in keys:
                    combo.addItem(f"{k.label} ({k.algorithm}) [{k.fingerprint[:12]}…]", k.fingerprint)
        except Exception:
            pass

    # ------------------------------------------------------------------
    # Actions
    # ------------------------------------------------------------------

    def _browse_input_file(self) -> None:
        path, _ = QFileDialog.getOpenFileName(self, "Select File to Sign")
        if path:
            self.file_input.setText(path)
            if not self.file_output.text():
                self.file_output.setText(path + ".sig")

    def _browse_output_file(self) -> None:
        path, _ = QFileDialog.getSaveFileName(self, "Save Signature As", "", "Signature Files (*.sig);;All Files (*)")
        if path:
            self.file_output.setText(path)

    def _get_selected_key(self, combo: QComboBox) -> tuple[str, str] | None:
        """Return (fingerprint, algorithm) for selected key, or None."""
        idx = combo.currentIndex()
        if idx < 0:
            QMessageBox.warning(self, "Sign", "No signing key selected.")
            return None
        fp = combo.currentData()
        try:
            ks = hbz.KeyStore()
            meta = ks.get_key_metadata(fp)
            if meta is None:
                QMessageBox.warning(self, "Sign", "Selected key not found in keystore.")
                return None
            return (fp, meta.algorithm.lower())
        except Exception as e:
            QMessageBox.warning(self, "Sign", f"Key error: {e}")
            return None

    def _sign_file(self) -> None:
        input_path = self.file_input.text().strip()
        output_path = self.file_output.text().strip() or (input_path + ".sig")
        pw = self.file_passphrase.text()

        if not input_path:
            QMessageBox.warning(self, "Sign", "Select a file to sign.")
            return
        if not pw:
            QMessageBox.warning(self, "Sign", "Enter the private key passphrase.")
            return

        info = self._get_selected_key(self.file_key_combo)
        if not info:
            return
        fp, algo = info

        try:
            ks = hbz.KeyStore()
            priv_data = ks.load_private_key(fp, pw.encode())
            message = Path(input_path).read_bytes()

            import base64
            if algo in ("ed25519",):
                sig = hbz.ed25519_sign(priv_data.decode(), message)
            elif algo in ("rsa2048", "rsa4096"):
                sig = hbz.rsa_sign(priv_data.decode(), message)
            elif algo == "pgp":
                sig = hbz.pgp_sign(message, priv_data.decode())
            else:
                QMessageBox.warning(self, "Sign", f"Unsupported algo: {algo}")
                return

            Path(output_path).write_bytes(sig)
            self.file_status.setText(f"✅ Signature saved to {output_path}")
            audit_safe(hbz.audit_log_data_signed, algo.upper(), fp, "source=gui, view=sign")
        except Exception as e:
            self.file_status.setText(f"❌ {e}")
            QMessageBox.critical(self, "Sign Failed", str(e))

    def _sign_text(self) -> None:
        message = self.text_input.toPlainText().encode("utf-8")
        pw = self.text_passphrase.text()

        if not message:
            QMessageBox.warning(self, "Sign", "Enter a message to sign.")
            return
        if not pw:
            QMessageBox.warning(self, "Sign", "Enter the private key passphrase.")
            return

        info = self._get_selected_key(self.text_key_combo)
        if not info:
            return
        fp, algo = info

        try:
            import base64
            ks = hbz.KeyStore()
            priv_data = ks.load_private_key(fp, pw.encode())

            if algo in ("ed25519",):
                sig = hbz.ed25519_sign(priv_data.decode(), message)
            elif algo in ("rsa2048", "rsa4096"):
                sig = hbz.rsa_sign(priv_data.decode(), message)
            elif algo == "pgp":
                sig = hbz.pgp_sign(message, priv_data.decode())
            else:
                QMessageBox.warning(self, "Sign", f"Unsupported algo: {algo}")
                return

            self.text_output.setPlainText(base64.b64encode(sig).decode())
            audit_safe(hbz.audit_log_data_signed, algo.upper(), fp, "source=gui, view=sign")
        except Exception as e:
            QMessageBox.critical(self, "Sign Failed", str(e))
