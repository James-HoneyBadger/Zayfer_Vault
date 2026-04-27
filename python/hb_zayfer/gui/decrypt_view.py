"""Decrypt view — decrypt files or text."""

from __future__ import annotations

from PySide6.QtCore import QThreadPool
from PySide6.QtWidgets import (
    QCheckBox,
    QComboBox,
    QFileDialog,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMessageBox,
    QProgressBar,
    QPushButton,
    QTabWidget,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

import hb_zayfer as hbz
from hb_zayfer.gui.audit_utils import log_file_decrypted
from hb_zayfer.gui.clipboard import secure_copy
from hb_zayfer.gui.dragdrop import DragDropFileInput
from hb_zayfer.gui.theme import Theme
from hb_zayfer.gui.workers import CryptoWorker


class DecryptView(QWidget):
    """File & text decryption interface."""

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
        layout.addWidget(self.tabs)

        self.progress = QProgressBar()
        self.progress.setVisible(False)
        layout.addWidget(self.progress)

        layout.addStretch()

    # ---- File tab ----

    def _build_file_tab(self) -> QWidget:
        w = QWidget()
        layout = QVBoxLayout(w)
        layout.setSpacing(10)

        # Input file
        row = QHBoxLayout()
        row.setSpacing(8)
        row.addWidget(QLabel("Input file:"))
        self.file_input = DragDropFileInput(placeholder="Drop .hbzf file or browse...")
        row.addWidget(self.file_input, 1)
        browse = QPushButton("Browse")
        browse.setMaximumWidth(80)
        browse.clicked.connect(self._browse_input)
        row.addWidget(browse)
        layout.addLayout(row)

        # Output file
        row2 = QHBoxLayout()
        row2.setSpacing(8)
        row2.addWidget(QLabel("Output file:"))
        self.file_output = QLineEdit()
        self.file_output.setPlaceholderText("Auto-detected from input")
        row2.addWidget(self.file_output, 1)
        browse2 = QPushButton("Browse")
        browse2.setMaximumWidth(80)
        browse2.clicked.connect(self._browse_output)
        row2.addWidget(browse2)
        layout.addLayout(row2)

        # Header info
        self.header_label = QLabel("")
        self.header_label.setStyleSheet("color: palette(mid); font-style: italic; font-size: 11px;")
        layout.addWidget(self.header_label)

        # Key material
        opts = QGroupBox("Decryption Key")
        opts_layout = QVBoxLayout(opts)
        opts_layout.setSpacing(10)

        pw_row = QHBoxLayout()
        pw_row.addWidget(QLabel("Passphrase:"))
        self.passphrase_input = QLineEdit()
        self.passphrase_input.setEchoMode(QLineEdit.EchoMode.Password)
        pw_row.addWidget(self.passphrase_input, 1)
        opts_layout.addLayout(pw_row)

        key_row = QHBoxLayout()
        key_row.addWidget(QLabel("Private key:"))
        self.key_combo = QComboBox()
        self.key_combo.setPlaceholderText("Select key for RSA/X25519 encrypted files")
        self.key_combo.setVisible(False)
        key_row.addWidget(self.key_combo, 1)
        opts_layout.addLayout(key_row)

        self.key_warning = QLabel("⚠ No key selected - file will not decrypt")
        self.key_warning.setStyleSheet("color: #dc3545; font-weight: bold;")
        self.key_warning.setVisible(False)
        opts_layout.addWidget(self.key_warning)

        # Show password toggle
        self.show_password_check = QCheckBox("Show passphrase")
        self.show_password_check.stateChanged.connect(self._toggle_password_visibility)
        opts_layout.addWidget(self.show_password_check)

        layout.addWidget(opts)

        # Decrypt button
        self.decrypt_btn = QPushButton("Decrypt File")
        self.decrypt_btn.setStyleSheet(Theme.get_success_button_style())
        self.decrypt_btn.clicked.connect(self._do_decrypt_file)
        layout.addWidget(self.decrypt_btn)

        return w

    # ---- Text tab ----

    def _build_text_tab(self) -> QWidget:
        w = QWidget()
        layout = QVBoxLayout(w)

        layout.addWidget(QLabel("Encrypted input (Base64):"))
        self.text_input = QTextEdit()
        self.text_input.setPlaceholderText("Paste Base64-encoded encrypted data...")
        layout.addWidget(self.text_input, 1)

        pw_row = QHBoxLayout()
        pw_row.addWidget(QLabel("Passphrase:"))
        self.text_passphrase = QLineEdit()
        self.text_passphrase.setEchoMode(QLineEdit.EchoMode.Password)
        pw_row.addWidget(self.text_passphrase, 1)
        layout.addLayout(pw_row)

        # Show password toggle for text tab
        self.show_text_password_check = QCheckBox("Show passphrase")
        self.show_text_password_check.stateChanged.connect(self._toggle_text_password_visibility)
        layout.addWidget(self.show_text_password_check)

        btn = QPushButton("Decrypt Text")
        btn.setStyleSheet(Theme.get_success_button_style())
        btn.clicked.connect(self._do_decrypt_text)
        layout.addWidget(btn)

        layout.addWidget(QLabel("Decrypted plaintext:"))
        self.text_output = QTextEdit()
        self.text_output.setReadOnly(True)
        layout.addWidget(self.text_output, 1)

        # Copy output button
        copy_btn = QPushButton("📋 Copy Output")
        copy_btn.clicked.connect(self._copy_decrypted_output)
        layout.addWidget(copy_btn)

        return w

    # ---- Actions ----

    def _toggle_password_visibility(self, state: int) -> None:
        """Toggle visibility of file tab passphrase."""
        mode = QLineEdit.EchoMode.Normal if state else QLineEdit.EchoMode.Password
        self.passphrase_input.setEchoMode(mode)

    def _toggle_text_password_visibility(self, state: int) -> None:
        """Toggle visibility of text tab passphrase."""
        mode = QLineEdit.EchoMode.Normal if state else QLineEdit.EchoMode.Password
        self.text_passphrase.setEchoMode(mode)

    def _browse_input(self) -> None:
        path, _ = QFileDialog.getOpenFileName(self, "Select HBZF file", filter="HBZF files (*.hbzf);;All files (*)")
        if path:
            self.file_input.setText(path)
            if path.endswith(".hbzf"):
                self.file_output.setText(path[:-5])
            self._inspect_header(path)

    def _browse_output(self) -> None:
        path, _ = QFileDialog.getSaveFileName(self, "Save decrypted file")
        if path:
            self.file_output.setText(path)

    def _inspect_header(self, path: str) -> None:
        """Read the HBZF header and show info."""
        try:
            with open(path, "rb") as f:
                head = f.read(8)
            if len(head) < 8 or head[:4] != b"HBZF":
                self.header_label.setText("Not a valid HBZF file")
                self.key_combo.setVisible(False)
                self.key_warning.setVisible(False)
                return
            algos = {0x01: "AES-256-GCM", 0x02: "ChaCha20-Poly1305"}
            wraps = {0x00: "Password", 0x01: "RSA-OAEP", 0x02: "X25519-ECDH"}
            algo = algos.get(head[5], f"0x{head[5]:02x}")
            wrap = wraps.get(head[7], f"0x{head[7]:02x}")
            self.header_label.setText(f"Format: HBZF v{head[4]}  |  Cipher: {algo}  |  Mode: {wrap}")

            # If asymmetric, populate key selector
            if head[7] in (0x01, 0x02):  # RSA or X25519
                self.key_combo.setVisible(True)
                self.key_combo.clear()
                try:
                    ks = hbz.KeyStore()
                    all_keys = [k for k in ks.list_keys() if k.has_private]
                    if head[7] == 0x01:  # RSA
                        keys = [k for k in all_keys if k.algorithm in ("RSA-2048", "RSA-4096")]
                    else:  # X25519
                        keys = [k for k in all_keys if k.algorithm == "X25519"]

                    if not keys:
                        self.key_combo.addItem("No suitable keys found")
                        self.key_warning.setText(f"⚠ No {wrap} private keys in keyring")
                        self.key_warning.setVisible(True)
                    else:
                        for k in keys:
                            fp_short = k.fingerprint[:16]
                            self.key_combo.addItem(f"{k.label} ({fp_short}...)", k.fingerprint)
                        self.key_warning.setVisible(False)
                except Exception:
                    self.key_combo.addItem("Error loading keys")
                    self.key_warning.setVisible(True)
            else:
                self.key_combo.setVisible(False)
                self.key_warning.setVisible(False)
        except Exception:
            self.header_label.setText("")
            self.key_combo.setVisible(False)
            self.key_warning.setVisible(False)

    def _do_decrypt_file(self) -> None:
        inp = self.file_input.text().strip()
        out = self.file_output.text().strip()
        if not inp:
            QMessageBox.warning(self, "Error", "Please select an input file.")
            return
        if not out:
            out = inp[:-5] if inp.endswith(".hbzf") else inp + ".dec"

        # Read header to determine mode
        try:
            with open(inp, "rb") as f:
                head = f.read(8)
            if len(head) < 8 or head[:4] != b"HBZF":
                QMessageBox.warning(self, "Error", "Not a valid HBZF file.")
                return
            wrapping_id = head[7]
        except Exception as e:
            QMessageBox.critical(self, "Error", str(e))
            return

        if wrapping_id == 0x00:  # Password
            pw = self.passphrase_input.text()
            if not pw:
                QMessageBox.warning(self, "Error", "Enter the passphrase.")
                return
            worker = CryptoWorker(hbz.decrypt_file, inp, out, passphrase=pw.encode("utf-8"))
        elif wrapping_id in (0x01, 0x02):  # RSA or X25519
            pw = self.passphrase_input.text()
            if not pw:
                QMessageBox.warning(self, "Error", "Enter the key passphrase.")
                return

            # Get selected key fingerprint
            if self.key_combo.currentIndex() < 0:
                QMessageBox.warning(self, "Error", "Please select a private key.")
                return
            fp = self.key_combo.currentData()
            if not fp:
                QMessageBox.warning(self, "Error", "No suitable key selected.")
                return

            try:
                ks = hbz.KeyStore()
                priv_data = ks.load_private_key(fp, pw.encode("utf-8"))
                if wrapping_id == 0x01:
                    worker = CryptoWorker(hbz.decrypt_file, inp, out, private_pem=priv_data.decode())
                else:
                    worker = CryptoWorker(hbz.decrypt_file, inp, out, secret_raw=priv_data)
            except Exception as e:
                QMessageBox.critical(self, "Error", str(e))
                return
        else:
            QMessageBox.warning(self, "Error", f"Unknown wrapping mode: 0x{wrapping_id:02x}")
            return

        self.decrypt_btn.setEnabled(False)
        self.progress.setVisible(True)
        self.progress.setRange(0, 0)

        worker.signals.result.connect(lambda _: self._on_decrypt_done(out))
        worker.signals.error.connect(self._on_decrypt_error)
        worker.signals.finished.connect(lambda: self.decrypt_btn.setEnabled(True))
        worker.signals.finished.connect(lambda: self.progress.setVisible(False))
        QThreadPool.globalInstance().start(worker)

    def _on_decrypt_done(self, path: str) -> None:
        inp = self.file_input.text().strip()
        algo = "UNKNOWN"
        try:
            with open(inp, "rb") as f:
                head = f.read(8)
            if len(head) >= 6:
                algo = {0x01: "AES-256-GCM", 0x02: "ChaCha20-Poly1305"}.get(head[5], "UNKNOWN")
        except Exception:
            pass

        size = None
        try:
            from pathlib import Path
            size = Path(path).stat().st_size
        except Exception:
            pass
        if inp:
            log_file_decrypted(algo, inp, size)

        self._notify("show_success", f"File decrypted: {path}")
        # Clear form after success
        self.file_input.clear()
        self.file_output.clear()
        self.passphrase_input.clear()
        self.header_label.clear()
        self.key_combo.setVisible(False)
        self.key_warning.setVisible(False)

    def _on_decrypt_error(self, error: str) -> None:
        self._notify("show_error", f"Decryption error: {error}")

    def _do_decrypt_text(self) -> None:
        import base64

        b64 = self.text_input.toPlainText().strip()
        pw = self.text_passphrase.text()
        if not b64:
            QMessageBox.warning(self, "Error", "Paste encrypted Base64 data.")
            return
        if not pw:
            QMessageBox.warning(self, "Error", "Enter the passphrase.")
            return

        data = base64.b64decode(b64)
        pw_bytes = pw.encode("utf-8")

        def _decrypt_text_work():
            return hbz.decrypt_data(data, passphrase=pw_bytes)

        from hb_zayfer.gui.workers import CryptoWorker
        worker = CryptoWorker(_decrypt_text_work)
        worker.signals.result.connect(
            lambda pt: self._on_text_decrypt_done(pt.decode("utf-8", errors="replace"))
        )
        worker.signals.error.connect(lambda err: QMessageBox.critical(self, "Error", err))
        QThreadPool.globalInstance().start(worker)

    def _on_text_decrypt_done(self, plaintext: str) -> None:
        self.text_output.setPlainText(plaintext)
        self._notify("show_success", "Text decrypted successfully")
        self.text_passphrase.clear()

    def _copy_decrypted_output(self) -> None:
        """Copy decrypted output to clipboard."""
        text = self.text_output.toPlainText()
        if not text:
            self._notify("show_warning", "Nothing to copy")
            return
        secure_copy(text)
        self._notify("show_success", "Decrypted text copied to clipboard")

    def _notify(self, method: str, message: str) -> None:
        """Show a notification via the main window's toast system."""
        w = self.window()
        if hasattr(w, "notifications"):
            getattr(w.notifications, method)(message)
            return
        if method == "show_error":
            QMessageBox.critical(self, "Error", message)
        else:
            QMessageBox.information(self, "Info", message)
