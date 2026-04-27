"""Verify view — verify signatures with Ed25519, RSA, or PGP public keys."""

from __future__ import annotations

from pathlib import Path

from PySide6.QtWidgets import (
    QComboBox,
    QFileDialog,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPushButton,
    QTabWidget,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

import hb_zayfer as hbz
from hb_zayfer.gui.audit_utils import audit_safe


class VerifyView(QWidget):
    """Verify file or text signatures."""

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

        # Original file
        row = QHBoxLayout()
        row.addWidget(QLabel("Original file:"))
        self.file_input = QLineEdit()
        self.file_input.setPlaceholderText("The file that was signed")
        row.addWidget(self.file_input, 1)
        browse_btn = QPushButton("Browse…")
        browse_btn.clicked.connect(self._browse_input_file)
        row.addWidget(browse_btn)
        layout.addLayout(row)

        # Signature file
        sig_row = QHBoxLayout()
        sig_row.addWidget(QLabel("Signature:"))
        self.file_sig = QLineEdit()
        self.file_sig.setPlaceholderText("Signature file (.sig)")
        sig_row.addWidget(self.file_sig, 1)
        sig_browse = QPushButton("Browse…")
        sig_browse.clicked.connect(self._browse_sig_file)
        sig_row.addWidget(sig_browse)
        layout.addLayout(sig_row)

        # Public key
        key_row = QHBoxLayout()
        key_row.addWidget(QLabel("Signer key:"))
        self.file_key_combo = QComboBox()
        self.file_key_combo.setMinimumWidth(350)
        key_row.addWidget(self.file_key_combo, 1)
        refresh_btn = QPushButton("↻")
        refresh_btn.setToolTip("Refresh key list")
        refresh_btn.setFixedWidth(30)
        refresh_btn.clicked.connect(self._refresh_keys)
        key_row.addWidget(refresh_btn)
        layout.addLayout(key_row)

        self.file_verify_btn = QPushButton("Verify Signature")
        self.file_verify_btn.clicked.connect(self._verify_file)
        layout.addWidget(self.file_verify_btn)

        self.file_result = QLabel("")
        self.file_result.setStyleSheet("font-size: 14px; padding: 8px;")
        layout.addWidget(self.file_result)
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

        layout.addWidget(QLabel("Original message:"))
        self.text_input = QTextEdit()
        self.text_input.setPlaceholderText("Paste the original message…")
        layout.addWidget(self.text_input, 1)

        layout.addWidget(QLabel("Signature (base64):"))
        self.text_sig_input = QTextEdit()
        self.text_sig_input.setPlaceholderText("Paste the base64 signature…")
        self.text_sig_input.setMaximumHeight(100)
        layout.addWidget(self.text_sig_input)

        # Public key
        key_row = QHBoxLayout()
        key_row.addWidget(QLabel("Signer key:"))
        self.text_key_combo = QComboBox()
        self.text_key_combo.setMinimumWidth(350)
        key_row.addWidget(self.text_key_combo, 1)
        layout.addLayout(key_row)

        self.text_verify_btn = QPushButton("Verify Signature")
        self.text_verify_btn.clicked.connect(self._verify_text)
        layout.addWidget(self.text_verify_btn)

        self.text_result = QLabel("")
        self.text_result.setStyleSheet("font-size: 14px; padding: 8px;")
        layout.addWidget(self.text_result)

        return w

    # ------------------------------------------------------------------
    # Key helpers
    # ------------------------------------------------------------------

    def _refresh_keys(self) -> None:
        """Populate key combos with verification-capable keys."""
        try:
            ks = hbz.KeyStore()
            keys = [
                k
                for k in ks.list_keys()
                if k.has_public and k.algorithm.lower() in ("ed25519", "rsa2048", "rsa4096", "pgp")
            ]
            for combo in (self.file_key_combo, self.text_key_combo):
                combo.clear()
                for k in keys:
                    combo.addItem(
                        f"{k.label} ({k.algorithm}) [{k.fingerprint[:12]}…]", k.fingerprint
                    )
        except Exception:
            pass

    # ------------------------------------------------------------------
    # Actions
    # ------------------------------------------------------------------

    def _browse_input_file(self) -> None:
        path, _ = QFileDialog.getOpenFileName(self, "Select Original File")
        if path:
            self.file_input.setText(path)

    def _browse_sig_file(self) -> None:
        path, _ = QFileDialog.getOpenFileName(
            self, "Select Signature File", "", "Signature Files (*.sig);;All Files (*)"
        )
        if path:
            self.file_sig.setText(path)

    def _get_key_info(self, combo: QComboBox) -> tuple[str, str] | None:
        """Return (fingerprint, algorithm) or None."""
        idx = combo.currentIndex()
        if idx < 0:
            QMessageBox.warning(self, "Verify", "No signer key selected.")
            return None
        fp = combo.currentData()
        try:
            ks = hbz.KeyStore()
            meta = ks.get_key_metadata(fp)
            return (fp, meta.algorithm.lower())
        except Exception as e:
            QMessageBox.warning(self, "Verify", f"Key error: {e}")
            return None

    def _verify_file(self) -> None:
        input_path = self.file_input.text().strip()
        sig_path = self.file_sig.text().strip()

        if not input_path:
            QMessageBox.warning(self, "Verify", "Select the original file.")
            return
        if not sig_path:
            QMessageBox.warning(self, "Verify", "Select the signature file.")
            return

        info = self._get_key_info(self.file_key_combo)
        if not info:
            return
        fp, algo = info

        try:
            ks = hbz.KeyStore()
            pub_data = ks.load_public_key(fp)
            message = Path(input_path).read_bytes()
            signature = Path(sig_path).read_bytes()

            valid = self._do_verify(algo, pub_data, message, signature)
            self._show_result(self.file_result, valid)
            audit_safe(
                hbz.audit_log_signature_verified, algo.upper(), fp, valid, "source=gui, view=verify"
            )
        except Exception as e:
            self.file_result.setText(f"❌ Error: {e}")
            self.file_result.setStyleSheet("font-size: 14px; padding: 8px; color: red;")

    def _verify_text(self) -> None:
        message = self.text_input.toPlainText().encode("utf-8")
        sig_b64 = self.text_sig_input.toPlainText().strip()

        if not message:
            QMessageBox.warning(self, "Verify", "Enter the original message.")
            return
        if not sig_b64:
            QMessageBox.warning(self, "Verify", "Enter the base64 signature.")
            return

        info = self._get_key_info(self.text_key_combo)
        if not info:
            return
        fp, algo = info

        try:
            import base64

            signature = base64.b64decode(sig_b64)
            ks = hbz.KeyStore()
            pub_data = ks.load_public_key(fp)

            valid = self._do_verify(algo, pub_data, message, signature)
            self._show_result(self.text_result, valid)
            audit_safe(
                hbz.audit_log_signature_verified, algo.upper(), fp, valid, "source=gui, view=verify"
            )
        except Exception as e:
            self.text_result.setText(f"❌ Error: {e}")
            self.text_result.setStyleSheet("font-size: 14px; padding: 8px; color: red;")

    def _do_verify(self, algo: str, pub_data: bytes, message: bytes, signature: bytes) -> bool:
        if algo in ("ed25519",):
            return hbz.ed25519_verify(pub_data.decode(), message, signature)
        elif algo in ("rsa2048", "rsa4096"):
            return hbz.rsa_verify(pub_data.decode(), message, signature)
        elif algo == "pgp":
            _, valid = hbz.pgp_verify(signature, pub_data.decode())
            return valid
        else:
            raise ValueError(f"Unsupported algorithm: {algo}")

    def _show_result(self, label: QLabel, valid: bool) -> None:
        if valid:
            label.setText("✅ Signature is VALID")
            label.setStyleSheet("font-size: 14px; padding: 8px; color: green; font-weight: bold;")
        else:
            label.setText("❌ Signature is INVALID")
            label.setStyleSheet("font-size: 14px; padding: 8px; color: red; font-weight: bold;")
