"""Decrypt view — decrypt files or text."""

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
    QFileDialog,
    QTextEdit,
    QGroupBox,
    QProgressBar,
    QMessageBox,
    QTabWidget,
)

import hb_zayfer as hbz
from hb_zayfer.gui.workers import CryptoWorker


class DecryptView(QWidget):
    """File & text decryption interface."""

    def __init__(self) -> None:
        super().__init__()
        self._setup_ui()

    def _setup_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 20, 20, 20)

        title = QLabel("<h2>Decrypt</h2>")
        layout.addWidget(title)

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

        # Input file
        row = QHBoxLayout()
        row.addWidget(QLabel("Input:"))
        self.file_input = QLineEdit()
        self.file_input.setPlaceholderText("Select HBZF file to decrypt...")
        row.addWidget(self.file_input, 1)
        browse = QPushButton("Browse...")
        browse.clicked.connect(self._browse_input)
        row.addWidget(browse)
        layout.addLayout(row)

        # Output file
        row2 = QHBoxLayout()
        row2.addWidget(QLabel("Output:"))
        self.file_output = QLineEdit()
        self.file_output.setPlaceholderText("Output path (auto-detected)")
        row2.addWidget(self.file_output, 1)
        browse2 = QPushButton("Browse...")
        browse2.clicked.connect(self._browse_output)
        row2.addWidget(browse2)
        layout.addLayout(row2)

        # Header info
        self.header_label = QLabel("")
        self.header_label.setStyleSheet("color: #8888aa; font-style: italic;")
        layout.addWidget(self.header_label)

        # Key material
        opts = QGroupBox("Decryption Key")
        opts_layout = QVBoxLayout(opts)

        pw_row = QHBoxLayout()
        pw_row.addWidget(QLabel("Passphrase:"))
        self.passphrase_input = QLineEdit()
        self.passphrase_input.setEchoMode(QLineEdit.EchoMode.Password)
        pw_row.addWidget(self.passphrase_input, 1)
        opts_layout.addLayout(pw_row)

        key_row = QHBoxLayout()
        key_row.addWidget(QLabel("Key (fingerprint):"))
        self.key_input = QLineEdit()
        self.key_input.setPlaceholderText("For RSA/X25519 modes — fingerprint prefix")
        key_row.addWidget(self.key_input, 1)
        opts_layout.addLayout(key_row)

        layout.addWidget(opts)

        # Decrypt button
        self.decrypt_btn = QPushButton("Decrypt File")
        self.decrypt_btn.setStyleSheet("QPushButton { background-color: #28a745; font-weight: bold; font-size: 14px; padding: 10px; }")
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

        btn = QPushButton("Decrypt Text")
        btn.setStyleSheet("QPushButton { background-color: #28a745; font-weight: bold; }")
        btn.clicked.connect(self._do_decrypt_text)
        layout.addWidget(btn)

        layout.addWidget(QLabel("Decrypted plaintext:"))
        self.text_output = QTextEdit()
        self.text_output.setReadOnly(True)
        layout.addWidget(self.text_output, 1)

        return w

    # ---- Actions ----

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
                return
            algos = {0x01: "AES-256-GCM", 0x02: "ChaCha20-Poly1305"}
            wraps = {0x00: "Password", 0x01: "RSA-OAEP", 0x02: "X25519-ECDH"}
            algo = algos.get(head[5], f"0x{head[5]:02x}")
            wrap = wraps.get(head[7], f"0x{head[7]:02x}")
            self.header_label.setText(f"Format: HBZF v{head[4]}  |  Cipher: {algo}  |  Mode: {wrap}")
        except Exception:
            self.header_label.setText("")

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
            fp_hint = self.key_input.text().strip()
            pw = self.passphrase_input.text()
            if not pw:
                QMessageBox.warning(self, "Error", "Enter the key passphrase.")
                return
            try:
                ks = hbz.KeyStore()
                fps = ks.resolve_recipient(fp_hint) if fp_hint else []
                if not fps:
                    # List all private keys
                    all_keys = [k for k in ks.list_keys() if k.has_private]
                    if not all_keys:
                        QMessageBox.warning(self, "Error", "No private keys found in keyring.")
                        return
                    fps = [all_keys[0].fingerprint]
                fp = fps[0]
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
        QMessageBox.information(self, "Success", f"File decrypted:\n{path}")

    def _on_decrypt_error(self, error: str) -> None:
        QMessageBox.critical(self, "Decryption Error", error)

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

        try:
            data = base64.b64decode(b64)
            plaintext = hbz.decrypt_data(data, passphrase=pw.encode("utf-8"))
            self.text_output.setPlainText(plaintext.decode("utf-8", errors="replace"))
        except Exception as e:
            QMessageBox.critical(self, "Error", str(e))
