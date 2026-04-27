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
    QCheckBox,
    QCompleter,
    QApplication,
)

import hb_zayfer as hbz
from hb_zayfer.gui.clipboard import secure_copy
from hb_zayfer.gui.workers import CryptoWorker
from hb_zayfer.gui.password_strength import PasswordStrengthMeter
from hb_zayfer.gui.dragdrop import DragDropFileInput
from hb_zayfer.gui.audit_utils import log_file_encrypted
from hb_zayfer.gui.theme import Theme
from hb_zayfer.gui.settings_manager import CryptoConfig


def _load_kdf_settings() -> dict:
    """KDF parameters for ``hbz`` encrypt calls (delegates to :class:`CryptoConfig`)."""
    return CryptoConfig.instance().kdf_settings()


def _load_default_cipher() -> str:
    """Default cipher (delegates to :class:`CryptoConfig`)."""
    return CryptoConfig.instance().default_cipher()


class EncryptView(QWidget):
    """File & text encryption interface."""

    def __init__(self) -> None:
        super().__init__()
        self._setup_ui()

    def _setup_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.setContentsMargins(16, 12, 16, 12)
        layout.setSpacing(12)

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
        layout.setSpacing(10)

        # Input file
        row = QHBoxLayout()
        row.setSpacing(8)
        row.addWidget(QLabel("Input file:"))
        self.file_input = DragDropFileInput(placeholder="Drop file or browse...")
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
        self.file_output.setPlaceholderText("Auto: input.hbzf")
        row2.addWidget(self.file_output, 1)
        browse2 = QPushButton("Browse")
        browse2.setMaximumWidth(80)
        browse2.clicked.connect(self._browse_output)
        row2.addWidget(browse2)
        layout.addLayout(row2)

        # Options
        opts = QGroupBox("Encryption Options")
        opts_layout = QVBoxLayout(opts)
        opts_layout.setSpacing(10)

        # Algorithm
        algo_row = QHBoxLayout()
        algo_row.setSpacing(8)
        algo_row.addWidget(QLabel("Algorithm:"))
        self.algo_combo = QComboBox()
        self.algo_combo.addItems(["AES-256-GCM", "ChaCha20-Poly1305"])
        _default_cipher = _load_default_cipher()
        _idx = self.algo_combo.findText(_default_cipher)
        if _idx >= 0:
            self.algo_combo.setCurrentIndex(_idx)
        algo_row.addWidget(self.algo_combo)
        algo_row.addStretch()
        opts_layout.addLayout(algo_row)

        # Wrapping mode
        wrap_row = QHBoxLayout()
        wrap_row.setSpacing(8)
        self.wrap_password = QRadioButton("Password")
        self.wrap_password.setChecked(True)
        self.wrap_recipient = QRadioButton("Public key")
        wrap_row.addWidget(QLabel("Encrypt with:"))
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

        # Passphrase confirmation
        pw_confirm_row = QHBoxLayout()
        pw_confirm_row.addWidget(QLabel("Confirm:"))
        self.passphrase_confirm = QLineEdit()
        self.passphrase_confirm.setEchoMode(QLineEdit.EchoMode.Password)
        self.passphrase_confirm.setPlaceholderText("Re-enter passphrase")
        pw_confirm_row.addWidget(self.passphrase_confirm, 1)
        opts_layout.addLayout(pw_confirm_row)

        # Password strength meter for file encryption
        self.file_strength_meter = PasswordStrengthMeter()
        opts_layout.addWidget(self.file_strength_meter)
        self.passphrase_input.textChanged.connect(lambda: self.file_strength_meter.update_strength(self.passphrase_input.text()))
        
        # Match indicator
        self.match_label = QLabel("")
        opts_layout.addWidget(self.match_label)
        self.passphrase_confirm.textChanged.connect(self._check_passphrase_match)

        # Show password toggle
        self.show_password_check = QCheckBox("Show passphrases")
        self.show_password_check.stateChanged.connect(self._toggle_password_visibility)
        opts_layout.addWidget(self.show_password_check)

        # Recipient
        rcpt_row = QHBoxLayout()
        rcpt_row.addWidget(QLabel("Recipient:"))
        self.recipient_input = QLineEdit()
        self.recipient_input.setPlaceholderText("Contact name or fingerprint prefix")
        self.recipient_input.setEnabled(False)
        rcpt_row.addWidget(self.recipient_input, 1)
        opts_layout.addLayout(rcpt_row)
        
        # Populate recipient autocomplete from contacts and keyring
        self._setup_recipient_completer()

        self.wrap_password.toggled.connect(lambda c: self.passphrase_input.setEnabled(c))
        self.wrap_password.toggled.connect(lambda c: self.passphrase_confirm.setEnabled(c))
        self.wrap_password.toggled.connect(lambda c: self.file_strength_meter.setVisible(c))
        self.wrap_password.toggled.connect(lambda c: self.match_label.setVisible(c))
        self.wrap_password.toggled.connect(lambda c: self.recipient_input.setEnabled(not c))

        layout.addWidget(opts)

        # Encrypt button
        self.encrypt_btn = QPushButton("Encrypt File")
        self.encrypt_btn.setStyleSheet(Theme.get_primary_button_style())
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

        # Confirmation for text
        pw_confirm_row = QHBoxLayout()
        pw_confirm_row.addWidget(QLabel("Confirm:"))
        self.text_passphrase_confirm = QLineEdit()
        self.text_passphrase_confirm.setEchoMode(QLineEdit.EchoMode.Password)
        self.text_passphrase_confirm.setPlaceholderText("Re-enter passphrase")
        pw_confirm_row.addWidget(self.text_passphrase_confirm, 1)
        layout.addLayout(pw_confirm_row)

        # Password strength meter for text encryption
        self.text_strength_meter = PasswordStrengthMeter()
        layout.addWidget(self.text_strength_meter)
        self.text_passphrase.textChanged.connect(lambda: self.text_strength_meter.update_strength(self.text_passphrase.text()))
        
        # Match indicator for text tab
        self.text_match_label = QLabel("")
        layout.addWidget(self.text_match_label)
        self.text_passphrase_confirm.textChanged.connect(self._check_text_passphrase_match)

        # Show password toggle for text tab
        self.show_text_password_check = QCheckBox("Show passphrases")
        self.show_text_password_check.stateChanged.connect(self._toggle_text_password_visibility)
        layout.addWidget(self.show_text_password_check)

        algo_row = QHBoxLayout()
        algo_row.addWidget(QLabel("Cipher:"))
        self.text_algo = QComboBox()
        self.text_algo.addItems(["AES-256-GCM", "ChaCha20-Poly1305"])
        _idx2 = self.text_algo.findText(_load_default_cipher())
        if _idx2 >= 0:
            self.text_algo.setCurrentIndex(_idx2)
        algo_row.addWidget(self.text_algo)
        algo_row.addStretch()
        layout.addLayout(algo_row)

        btn = QPushButton("Encrypt Text")
        btn.setStyleSheet(Theme.get_primary_button_style())
        btn.clicked.connect(self._do_encrypt_text)
        layout.addWidget(btn)

        layout.addWidget(QLabel("Encrypted output (Base64):"))
        self.text_output = QTextEdit()
        self.text_output.setReadOnly(True)
        layout.addWidget(self.text_output, 1)

        # Copy output button
        copy_btn = QPushButton("📋 Copy Output")
        copy_btn.clicked.connect(self._copy_encrypted_output)
        layout.addWidget(copy_btn)

        return w

    # ---- Actions ----

    def _toggle_password_visibility(self, state: int) -> None:
        """Toggle visibility of file tab passphrases."""
        mode = QLineEdit.EchoMode.Normal if state else QLineEdit.EchoMode.Password
        self.passphrase_input.setEchoMode(mode)
        self.passphrase_confirm.setEchoMode(mode)

    def _toggle_text_password_visibility(self, state: int) -> None:
        """Toggle visibility of text tab passphrases."""
        mode = QLineEdit.EchoMode.Normal if state else QLineEdit.EchoMode.Password
        self.text_passphrase.setEchoMode(mode)
        self.text_passphrase_confirm.setEchoMode(mode)

    def _check_passphrase_match(self) -> None:
        """Check if passphrase and confirmation match."""
        self._update_match_label(
            self.passphrase_input.text(),
            self.passphrase_confirm.text(),
            self.match_label,
        )

    def _check_text_passphrase_match(self) -> None:
        """Check if text passphrase and confirmation match."""
        self._update_match_label(
            self.text_passphrase.text(),
            self.text_passphrase_confirm.text(),
            self.text_match_label,
        )

    @staticmethod
    def _update_match_label(pw: str, confirm: str, label: QLabel) -> None:
        """Update a match indicator label."""
        if not confirm:
            label.setText("")
            return
        if pw == confirm:
            label.setText("✓ Passphrases match")
            label.setStyleSheet("color: #28a745;")
        else:
            label.setText("✗ Passphrases do not match")
            label.setStyleSheet("color: #dc3545;")

    def _setup_recipient_completer(self) -> None:
        """Populate recipient autocomplete from contacts and keyring."""
        completions: list[str] = []
        try:
            ks = hbz.KeyStore()
            for c in ks.list_contacts():
                completions.append(c.name)
                if c.email:
                    completions.append(c.email)
            for k in ks.list_keys():
                if k.has_public:
                    completions.append(f"{k.label} ({k.fingerprint[:16]}...)")
        except Exception:
            pass
        completer = QCompleter(completions, self)
        completer.setCaseSensitivity(Qt.CaseSensitivity.CaseInsensitive)
        completer.setFilterMode(Qt.MatchFlag.MatchContains)
        self.recipient_input.setCompleter(completer)

    def _notify(self, method: str, message: str) -> None:
        """Show a notification via the main window's toast system."""
        w = self.window()
        if hasattr(w, "notifications"):
            getattr(w.notifications, method)(message)
            return
        # Fallback to message box
        if method == "show_error":
            QMessageBox.critical(self, "Error", message)
        else:
            QMessageBox.information(self, "Info", message)

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
            confirm = self.passphrase_confirm.text()
            if pw != confirm:
                QMessageBox.warning(self, "Error", "Passphrases do not match.")
                return
            worker = CryptoWorker(
                hbz.encrypt_file, inp, out,
                algorithm=algo, wrapping="password", passphrase=pw.encode("utf-8"),
                **_load_kdf_settings(),
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
        inp = self.file_input.text().strip()
        algo = "AES-256-GCM" if self.algo_combo.currentIndex() == 0 else "ChaCha20-Poly1305"
        size = None
        try:
            from pathlib import Path
            if inp:
                size = Path(inp).stat().st_size
        except Exception:
            pass
        if inp:
            log_file_encrypted(algo, inp, size)
        
        self._notify("show_success", f"File encrypted: {path}")
        # Clear form after success
        self.file_input.clear()
        self.file_output.clear()
        self.passphrase_input.clear()
        self.passphrase_confirm.clear()
        self.match_label.clear()

    def _on_encrypt_error(self, error: str) -> None:
        self._notify("show_error", f"Encryption error: {error}")

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
        confirm = self.text_passphrase_confirm.text()
        if pw != confirm:
            QMessageBox.warning(self, "Error", "Passphrases do not match.")
            return

        algo = "aes" if self.text_algo.currentIndex() == 0 else "chacha"
        kdf_kw = _load_kdf_settings()
        text_bytes = text.encode("utf-8")
        pw_bytes = pw.encode("utf-8")

        def _encrypt_text_work():
            return hbz.encrypt_data(
                text_bytes, algorithm=algo, wrapping="password",
                passphrase=pw_bytes, **kdf_kw,
            )

        worker = CryptoWorker(_encrypt_text_work)
        worker.signals.result.connect(
            lambda encrypted: self._on_text_encrypt_done(base64.b64encode(encrypted).decode())
        )
        worker.signals.error.connect(lambda err: QMessageBox.critical(self, "Error", err))
        QThreadPool.globalInstance().start(worker)

    def _on_text_encrypt_done(self, b64_output: str) -> None:
        self.text_output.setPlainText(b64_output)
        self._notify("show_success", "Text encrypted successfully")
        self.text_passphrase.clear()
        self.text_passphrase_confirm.clear()
        self.text_match_label.clear()

    def _copy_encrypted_output(self) -> None:
        """Copy encrypted output to clipboard."""
        text = self.text_output.toPlainText()
        if not text:
            self._notify("show_warning", "Nothing to copy")
            return
        secure_copy(text)
        self._notify("show_success", "Encrypted output copied to clipboard")
