"""Key generation view."""

from __future__ import annotations

from PySide6.QtCore import QThreadPool
from PySide6.QtWidgets import (
    QCheckBox,
    QComboBox,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMessageBox,
    QProgressBar,
    QPushButton,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

from hb_zayfer.gui.audit_utils import log_key_generated
from hb_zayfer.gui.password_strength import PasswordStrengthMeter
from hb_zayfer.gui.theme import Theme
from hb_zayfer.gui.workers import CryptoWorker
from hb_zayfer.services import KeyService


class KeygenView(QWidget):
    """Generate new key pairs."""

    def __init__(self) -> None:
        super().__init__()
        self._setup_ui()

    def _setup_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.setContentsMargins(16, 12, 16, 12)
        layout.setSpacing(12)

        # Options
        opts = QGroupBox("Key Parameters")
        opts_layout = QVBoxLayout(opts)

        # Algorithm
        algo_row = QHBoxLayout()
        algo_row.addWidget(QLabel("Algorithm:"))
        self.algo_combo = QComboBox()
        self.algo_combo.addItems(["RSA-2048", "RSA-4096", "Ed25519", "X25519", "PGP/GPG"])
        algo_row.addWidget(self.algo_combo)
        algo_row.addStretch()
        opts_layout.addLayout(algo_row)

        # Label
        label_row = QHBoxLayout()
        label_row.addWidget(QLabel("Label:"))
        self.label_input = QLineEdit()
        self.label_input.setPlaceholderText("My encryption key")
        label_row.addWidget(self.label_input, 1)
        opts_layout.addLayout(label_row)

        # User ID (PGP only)
        self.uid_row_widget = QWidget()
        uid_row = QHBoxLayout(self.uid_row_widget)
        uid_row.setContentsMargins(0, 0, 0, 0)
        uid_row.addWidget(QLabel("User ID:"))
        self.uid_input = QLineEdit()
        self.uid_input.setPlaceholderText("Name <email@example.com>")
        uid_row.addWidget(self.uid_input, 1)
        self.uid_row_widget.setVisible(False)  # Hidden until PGP selected
        opts_layout.addWidget(self.uid_row_widget)

        # Show/hide UID based on algorithm
        self.algo_combo.currentIndexChanged.connect(self._on_algo_changed)

        # Passphrase
        pw_row = QHBoxLayout()
        pw_row.addWidget(QLabel("Passphrase:"))
        self.pw_input = QLineEdit()
        self.pw_input.setEchoMode(QLineEdit.EchoMode.Password)
        self.pw_input.setPlaceholderText("Protects the private key")
        pw_row.addWidget(self.pw_input, 1)
        opts_layout.addLayout(pw_row)

        pw2_row = QHBoxLayout()
        pw2_row.addWidget(QLabel("Confirm:"))
        self.pw2_input = QLineEdit()
        self.pw2_input.setEchoMode(QLineEdit.EchoMode.Password)
        pw2_row.addWidget(self.pw2_input, 1)
        opts_layout.addLayout(pw2_row)

        # Password strength meter
        self.strength_meter = PasswordStrengthMeter()
        opts_layout.addWidget(self.strength_meter)
        self.pw_input.textChanged.connect(
            lambda: self.strength_meter.update_strength(self.pw_input.text())
        )

        # Show password toggle
        self.show_password_check = QCheckBox("Show passphrases")
        self.show_password_check.stateChanged.connect(self._toggle_password_visibility)
        opts_layout.addWidget(self.show_password_check)

        layout.addWidget(opts)

        # Generate button
        gen_btn_layout = QHBoxLayout()
        self.gen_btn = QPushButton("Generate Key Pair")
        self.gen_btn.setMinimumWidth(150)
        self.gen_btn.setStyleSheet(Theme.get_primary_button_style())
        self.gen_btn.clicked.connect(self._do_generate)
        gen_btn_layout.addWidget(self.gen_btn)
        gen_btn_layout.addStretch()
        layout.addLayout(gen_btn_layout)

        # Progress
        self.progress = QProgressBar()
        self.progress.setVisible(False)
        layout.addWidget(self.progress)

        # Result output
        self.result_text = QTextEdit()
        self.result_text.setReadOnly(True)
        self.result_text.setMaximumHeight(150)
        self.result_text.setVisible(False)
        layout.addWidget(self.result_text)

        layout.addStretch()

    def _on_algo_changed(self, index: int) -> None:
        """Show/hide PGP User ID field based on algorithm."""
        is_pgp = index == 4  # PGP/GPG is index 4
        self.uid_row_widget.setVisible(is_pgp)

    def _toggle_password_visibility(self, state: int) -> None:
        """Toggle visibility of passphrases."""
        mode = QLineEdit.EchoMode.Normal if state else QLineEdit.EchoMode.Password
        self.pw_input.setEchoMode(mode)
        self.pw2_input.setEchoMode(mode)

    def _do_generate(self) -> None:
        label = self.label_input.text().strip()
        if not label:
            QMessageBox.warning(self, "Error", "Please enter a key label.")
            return

        pw = self.pw_input.text()
        pw2 = self.pw2_input.text()
        if not pw:
            QMessageBox.warning(self, "Error", "Please enter a passphrase.")
            return
        if pw != pw2:
            QMessageBox.warning(self, "Error", "Passphrases do not match.")
            return

        algo_idx = self.algo_combo.currentIndex()
        algo_map = ["rsa2048", "rsa4096", "ed25519", "x25519", "pgp"]
        algorithm = algo_map[algo_idx]
        uid = self.uid_input.text().strip() or label

        self.gen_btn.setEnabled(False)
        self.progress.setVisible(True)
        self.progress.setRange(0, 0)

        worker = CryptoWorker(self._generate_key, algorithm, label, uid, pw.encode("utf-8"))
        worker.signals.result.connect(self._on_gen_done)
        worker.signals.error.connect(self._on_gen_error)
        worker.signals.finished.connect(lambda: self.gen_btn.setEnabled(True))
        worker.signals.finished.connect(lambda: self.progress.setVisible(False))
        QThreadPool.globalInstance().start(worker)

    @staticmethod
    def _generate_key(algorithm: str, label: str, uid: str, passphrase: bytes) -> str:
        """Generate a key and store it. Returns info string."""
        result = KeyService.generate_key(
            algorithm=algorithm,
            label=label,
            passphrase=passphrase,
            user_id=uid,
        )
        return result.to_display_text()

    def _on_gen_done(self, info: object) -> None:
        self.result_text.setVisible(True)
        info_text = str(info)
        self.result_text.setPlainText(info_text)
        fp = ""
        algo = ""
        for line in info_text.splitlines():
            if line.startswith("Fingerprint:"):
                fp = line.split(":", 1)[1].strip()
            if line.startswith("Algorithm:"):
                algo = line.split(":", 1)[1].strip()
        if fp:
            log_key_generated(algo or "KEY", fp)

        self._notify("show_success", "Key pair generated and stored")
        # Clear form after success
        self.label_input.clear()
        self.uid_input.clear()
        self.pw_input.clear()
        self.pw2_input.clear()
        self.strength_meter.update_strength("")

    def _on_gen_error(self, error: str) -> None:
        self._notify("show_error", f"Key generation error: {error}")

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
