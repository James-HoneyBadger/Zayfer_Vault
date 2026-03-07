"""Encrypt view — encrypt files or text."""

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
    QRadioButton,
    QProgressBar,
    QMessageBox,
    QTabWidget,
)

import hb_zayfer as hbz
from hb_zayfer.gui.workers import CryptoWorker


class EncryptView(QWidget):
    """File & text encryption interface."""

    def __init__(self) -> None:
        super().__init__()
        self._setup_ui()

    def _setup_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 20, 20, 20)

        title = QLabel("<h2>Encrypt</h2>")
        layout.addWidget(title)

        # Tabs: File / Text
        self.tabs = QTabWidget()
        self.tabs.addTab(self._build_file_tab(), "File")
        self.tabs.addTab(self._build_text_tab(), "Text")
        layout.addWidget(self.tabs)

        # Progress
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
        self.file_input.setPlaceholderText("Select file to encrypt...")
        row.addWidget(self.file_input, 1)
        browse = QPushButton("Browse...")
        browse.clicked.connect(self._browse_input)
        row.addWidget(browse)
        layout.addLayout(row)

        # Output file
        row2 = QHBoxLayout()
        row2.addWidget(QLabel("Output:"))
        self.file_output = QLineEdit()
        self.file_output.setPlaceholderText("Output path (default: <input>.hbzf)")
        row2.addWidget(self.file_output, 1)
        browse2 = QPushButton("Browse...")
        browse2.clicked.connect(self._browse_output)
        row2.addWidget(browse2)
        layout.addLayout(row2)

        # Options
        opts = QGroupBox("Options")
        opts_layout = QVBoxLayout(opts)

        # Algorithm
        algo_row = QHBoxLayout()
        algo_row.addWidget(QLabel("Cipher:"))
        self.algo_combo = QComboBox()
        self.algo_combo.addItems(["AES-256-GCM", "ChaCha20-Poly1305"])
        algo_row.addWidget(self.algo_combo)
        algo_row.addStretch()
        opts_layout.addLayout(algo_row)

        # Wrapping mode
        wrap_row = QHBoxLayout()
        self.wrap_password = QRadioButton("Password")
        self.wrap_password.setChecked(True)
        self.wrap_recipient = QRadioButton("Recipient key")
        wrap_row.addWidget(QLabel("Mode:"))
        wrap_row.addWidget(self.wrap_password)
        wrap_row.addWidget(self.wrap_recipient)
        wrap_row.addStretch()
        opts_layout.addLayout(wrap_row)

        # Passphrase
        pw_row = QHBoxLayout()
        pw_row.addWidget(QLabel("Passphrase:"))
        self.passphrase_input = QLineEdit()
        self.passphrase_input.setEchoMode(QLineEdit.EchoMode.Password)
        pw_row.addWidget(self.passphrase_input, 1)
        opts_layout.addLayout(pw_row)

        # Recipient
        rcpt_row = QHBoxLayout()
        rcpt_row.addWidget(QLabel("Recipient:"))
        self.recipient_input = QLineEdit()
        self.recipient_input.setPlaceholderText("Contact name or fingerprint prefix")
        self.recipient_input.setEnabled(False)
        rcpt_row.addWidget(self.recipient_input, 1)
        opts_layout.addLayout(rcpt_row)

        self.wrap_password.toggled.connect(lambda c: self.passphrase_input.setEnabled(c))
        self.wrap_password.toggled.connect(lambda c: self.recipient_input.setEnabled(not c))

        layout.addWidget(opts)

        # Encrypt button
        self.encrypt_btn = QPushButton("Encrypt File")
        self.encrypt_btn.setStyleSheet("QPushButton { background-color: #007acc; font-weight: bold; font-size: 14px; padding: 10px; }")
        self.encrypt_btn.clicked.connect(self._do_encrypt_file)
        layout.addWidget(self.encrypt_btn)

        return w

    # ---- Text tab ----

    def _build_text_tab(self) -> QWidget:
        w = QWidget()
        layout = QVBoxLayout(w)

        layout.addWidget(QLabel("Plaintext:"))
        self.text_input = QTextEdit()
        self.text_input.setPlaceholderText("Enter text to encrypt...")
        layout.addWidget(self.text_input, 1)

        # Passphrase for text
        pw_row = QHBoxLayout()
        pw_row.addWidget(QLabel("Passphrase:"))
        self.text_passphrase = QLineEdit()
        self.text_passphrase.setEchoMode(QLineEdit.EchoMode.Password)
        pw_row.addWidget(self.text_passphrase, 1)
        layout.addLayout(pw_row)

        algo_row = QHBoxLayout()
        algo_row.addWidget(QLabel("Cipher:"))
        self.text_algo = QComboBox()
        self.text_algo.addItems(["AES-256-GCM", "ChaCha20-Poly1305"])
        algo_row.addWidget(self.text_algo)
        algo_row.addStretch()
        layout.addLayout(algo_row)

        btn = QPushButton("Encrypt Text")
        btn.setStyleSheet("QPushButton { background-color: #007acc; font-weight: bold; }")
        btn.clicked.connect(self._do_encrypt_text)
        layout.addWidget(btn)

        layout.addWidget(QLabel("Encrypted output (Base64):"))
        self.text_output = QTextEdit()
        self.text_output.setReadOnly(True)
        layout.addWidget(self.text_output, 1)

        return w

    # ---- Actions ----

    def _browse_input(self) -> None:
        path, _ = QFileDialog.getOpenFileName(self, "Select file to encrypt")
        if path:
            self.file_input.setText(path)
            if not self.file_output.text():
                self.file_output.setText(path + ".hbzf")

    def _browse_output(self) -> None:
        path, _ = QFileDialog.getSaveFileName(self, "Save encrypted file", filter="HBZF files (*.hbzf);;All files (*)")
        if path:
            self.file_output.setText(path)

    def _do_encrypt_file(self) -> None:
        inp = self.file_input.text().strip()
        out = self.file_output.text().strip() or (inp + ".hbzf")
        if not inp:
            QMessageBox.warning(self, "Error", "Please select an input file.")
            return

        algo = "aes" if self.algo_combo.currentIndex() == 0 else "chacha"

        if self.wrap_password.isChecked():
            pw = self.passphrase_input.text()
            if not pw:
                QMessageBox.warning(self, "Error", "Please enter a passphrase.")
                return
            worker = CryptoWorker(
                hbz.encrypt_file, inp, out,
                algorithm=algo, wrapping="password", passphrase=pw.encode("utf-8"),
            )
        else:
            rcpt = self.recipient_input.text().strip()
            if not rcpt:
                QMessageBox.warning(self, "Error", "Please enter a recipient.")
                return
            try:
                ks = hbz.KeyStore()
                fps = ks.resolve_recipient(rcpt)
                if not fps:
                    QMessageBox.warning(self, "Error", f"No keys found for '{rcpt}'.")
                    return
                fp = fps[0]
                meta = ks.get_key_metadata(fp)
                pub_data = ks.load_public_key(fp)

                if meta and meta.algorithm in ("RSA-2048", "RSA-4096"):
                    worker = CryptoWorker(
                        hbz.encrypt_file, inp, out,
                        algorithm=algo, wrapping="rsa", recipient_public_pem=pub_data.decode(),
                    )
                elif meta and meta.algorithm == "X25519":
                    worker = CryptoWorker(
                        hbz.encrypt_file, inp, out,
                        algorithm=algo, wrapping="x25519", recipient_public_raw=pub_data,
                    )
                else:
                    QMessageBox.warning(self, "Error", f"Cannot encrypt with {meta.algorithm if meta else 'unknown'} key.")
                    return
            except Exception as e:
                QMessageBox.critical(self, "Error", str(e))
                return

        self.encrypt_btn.setEnabled(False)
        self.progress.setVisible(True)
        self.progress.setRange(0, 0)  # indeterminate

        worker.signals.result.connect(lambda _: self._on_encrypt_done(out))
        worker.signals.error.connect(self._on_encrypt_error)
        worker.signals.finished.connect(lambda: self.encrypt_btn.setEnabled(True))
        worker.signals.finished.connect(lambda: self.progress.setVisible(False))
        QThreadPool.globalInstance().start(worker)

    def _on_encrypt_done(self, path: str) -> None:
        QMessageBox.information(self, "Success", f"File encrypted:\n{path}")

    def _on_encrypt_error(self, error: str) -> None:
        QMessageBox.critical(self, "Encryption Error", error)

    def _do_encrypt_text(self) -> None:
        import base64

        text = self.text_input.toPlainText()
        pw = self.text_passphrase.text()
        if not text:
            QMessageBox.warning(self, "Error", "Please enter text to encrypt.")
            return
        if not pw:
            QMessageBox.warning(self, "Error", "Please enter a passphrase.")
            return

        algo = "aes" if self.text_algo.currentIndex() == 0 else "chacha"

        try:
            encrypted = hbz.encrypt_data(
                text.encode("utf-8"),
                algorithm=algo,
                wrapping="password",
                passphrase=pw.encode("utf-8"),
            )
            self.text_output.setPlainText(base64.b64encode(encrypted).decode())
        except Exception as e:
            QMessageBox.critical(self, "Error", str(e))
