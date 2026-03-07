"""Key generation view."""

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
    QGroupBox,
    QProgressBar,
    QMessageBox,
    QTextEdit,
)

import hb_zayfer as hbz
from hb_zayfer.gui.workers import CryptoWorker


class KeygenView(QWidget):
    """Generate new key pairs."""

    def __init__(self) -> None:
        super().__init__()
        self._setup_ui()

    def _setup_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 20, 20, 20)

        title = QLabel("<h2>Key Generation</h2>")
        layout.addWidget(title)

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

        # User ID (PGP)
        uid_row = QHBoxLayout()
        uid_row.addWidget(QLabel("User ID:"))
        self.uid_input = QLineEdit()
        self.uid_input.setPlaceholderText("Name <email@example.com> (PGP only)")
        uid_row.addWidget(self.uid_input, 1)
        opts_layout.addLayout(uid_row)

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

        layout.addWidget(opts)

        # Generate button
        self.gen_btn = QPushButton("Generate Key Pair")
        self.gen_btn.setStyleSheet("QPushButton { background-color: #007acc; font-weight: bold; font-size: 14px; padding: 10px; }")
        self.gen_btn.clicked.connect(self._do_generate)
        layout.addWidget(self.gen_btn)

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
        ks = hbz.KeyStore()

        if algorithm in ("rsa2048", "rsa4096"):
            bits = 2048 if algorithm == "rsa2048" else 4096
            priv_pem, pub_pem = hbz.rsa_generate(bits)
            fp = hbz.rsa_fingerprint(pub_pem)
            ks.store_private_key(fp, priv_pem.encode(), passphrase, algorithm, label)
            ks.store_public_key(fp, pub_pem.encode(), algorithm, label)
        elif algorithm == "ed25519":
            sk_pem, vk_pem = hbz.ed25519_generate()
            fp = hbz.ed25519_fingerprint(vk_pem)
            ks.store_private_key(fp, sk_pem.encode(), passphrase, algorithm, label)
            ks.store_public_key(fp, vk_pem.encode(), algorithm, label)
        elif algorithm == "x25519":
            sk_raw, pk_raw = hbz.x25519_generate()
            fp = hbz.x25519_fingerprint(pk_raw)
            ks.store_private_key(fp, sk_raw, passphrase, algorithm, label)
            ks.store_public_key(fp, pk_raw, algorithm, label)
        elif algorithm == "pgp":
            pub_arm, sec_arm = hbz.pgp_generate(uid)
            fp = hbz.pgp_fingerprint(pub_arm)
            ks.store_private_key(fp, sec_arm.encode(), passphrase, algorithm, label)
            ks.store_public_key(fp, pub_arm.encode(), algorithm, label)
        else:
            raise ValueError(f"Unknown algorithm: {algorithm}")

        return f"Algorithm: {algorithm.upper()}\nLabel: {label}\nFingerprint: {fp}"

    def _on_gen_done(self, info: object) -> None:
        self.result_text.setVisible(True)
        self.result_text.setPlainText(str(info))
        QMessageBox.information(self, "Success", "Key pair generated and stored.")

    def _on_gen_error(self, error: str) -> None:
        QMessageBox.critical(self, "Key Generation Error", error)
