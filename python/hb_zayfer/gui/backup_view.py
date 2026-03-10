"""Backup / Restore view — create, restore, and verify keyring backups."""

from __future__ import annotations

from pathlib import Path
from datetime import datetime

from PySide6.QtCore import Qt, QThreadPool
from PySide6.QtWidgets import (
    QWidget,
    QVBoxLayout,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QPushButton,
    QGroupBox,
    QFormLayout,
    QMessageBox,
    QFileDialog,
    QTextEdit,
    QProgressBar,
)

import hb_zayfer as hbz
from hb_zayfer.gui.workers import CryptoWorker


class BackupView(QWidget):
    """Create, restore, and verify keyring backups."""

    def __init__(self) -> None:
        super().__init__()
        self._setup_ui()

    # ------------------------------------------------------------------
    # UI setup
    # ------------------------------------------------------------------

    def _setup_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.setContentsMargins(16, 12, 16, 12)
        layout.setSpacing(16)

        title = QLabel("Backup & Restore")
        title.setStyleSheet("font-size: 16px; font-weight: bold;")
        layout.addWidget(title)

        # ---- Create backup ----
        create_box = QGroupBox("Create Backup")
        create_form = QFormLayout(create_box)

        self.backup_label_input = QLineEdit()
        self.backup_label_input.setPlaceholderText("Optional label for this backup")
        create_form.addRow("Label:", self.backup_label_input)

        path_row = QHBoxLayout()
        self.backup_path_input = QLineEdit()
        default_name = f"hb_zayfer_backup_{datetime.now():%Y%m%d}.hbzf-backup"
        self.backup_path_input.setText(str(Path.home() / default_name))
        path_row.addWidget(self.backup_path_input, 1)
        browse_btn = QPushButton("Browse…")
        browse_btn.clicked.connect(self._browse_backup_path)
        path_row.addWidget(browse_btn)
        create_form.addRow("Destination:", path_row)

        self.backup_pass_input = QLineEdit()
        self.backup_pass_input.setEchoMode(QLineEdit.EchoMode.Password)
        self.backup_pass_input.setPlaceholderText("Passphrase to encrypt the backup")
        create_form.addRow("Passphrase:", self.backup_pass_input)

        self.backup_pass_confirm = QLineEdit()
        self.backup_pass_confirm.setEchoMode(QLineEdit.EchoMode.Password)
        self.backup_pass_confirm.setPlaceholderText("Confirm passphrase")
        create_form.addRow("Confirm:", self.backup_pass_confirm)

        create_btn = QPushButton("Create Backup")
        create_btn.clicked.connect(self._create_backup)
        create_form.addRow("", create_btn)
        layout.addWidget(create_box)

        # ---- Restore / Verify backup ----
        restore_box = QGroupBox("Restore or Verify Backup")
        restore_form = QFormLayout(restore_box)

        restore_path_row = QHBoxLayout()
        self.restore_path_input = QLineEdit()
        self.restore_path_input.setPlaceholderText("Path to backup file")
        restore_path_row.addWidget(self.restore_path_input, 1)
        restore_browse_btn = QPushButton("Browse…")
        restore_browse_btn.clicked.connect(self._browse_restore_path)
        restore_path_row.addWidget(restore_browse_btn)
        restore_form.addRow("Backup file:", restore_path_row)

        self.restore_pass_input = QLineEdit()
        self.restore_pass_input.setEchoMode(QLineEdit.EchoMode.Password)
        self.restore_pass_input.setPlaceholderText("Passphrase for the backup")
        restore_form.addRow("Passphrase:", self.restore_pass_input)

        btn_row = QHBoxLayout()
        verify_btn = QPushButton("Verify Backup")
        verify_btn.setToolTip("Check backup integrity without restoring")
        verify_btn.clicked.connect(self._verify_backup)
        btn_row.addWidget(verify_btn)

        restore_btn = QPushButton("Restore Backup")
        restore_btn.setToolTip("Restore keys and contacts from backup")
        restore_btn.clicked.connect(self._restore_backup)
        btn_row.addWidget(restore_btn)
        restore_form.addRow("", btn_row)

        layout.addWidget(restore_box)

        # ---- Status / result ----
        self.status_output = QTextEdit()
        self.status_output.setReadOnly(True)
        self.status_output.setMaximumHeight(120)
        self.status_output.setPlaceholderText("Status messages will appear here…")
        layout.addWidget(self.status_output)

        layout.addStretch()

    # ------------------------------------------------------------------
    # Browse dialogs
    # ------------------------------------------------------------------

    def _browse_backup_path(self) -> None:
        path, _ = QFileDialog.getSaveFileName(
            self,
            "Save Backup As",
            self.backup_path_input.text(),
            "HB Zayfer Backup (*.hbzf-backup);;All Files (*)",
        )
        if path:
            self.backup_path_input.setText(path)

    def _browse_restore_path(self) -> None:
        path, _ = QFileDialog.getOpenFileName(
            self,
            "Open Backup File",
            str(Path.home()),
            "HB Zayfer Backup (*.hbzf-backup);;All Files (*)",
        )
        if path:
            self.restore_path_input.setText(path)

    # ------------------------------------------------------------------
    # Create backup
    # ------------------------------------------------------------------

    def _create_backup(self) -> None:
        dest = self.backup_path_input.text().strip()
        pw = self.backup_pass_input.text()
        pw_confirm = self.backup_pass_confirm.text()
        label = self.backup_label_input.text().strip() or None

        if not dest:
            QMessageBox.warning(self, "Backup", "Please specify a destination path.")
            return
        if not pw:
            QMessageBox.warning(self, "Backup", "Please enter a passphrase.")
            return
        if pw != pw_confirm:
            QMessageBox.warning(self, "Backup", "Passphrases do not match.")
            return

        try:
            ks = hbz.KeyStore()
            ks.create_backup(dest, pw.encode(), label)
            self.status_output.append(f"✅ Backup created: {dest}")
            self.backup_pass_input.clear()
            self.backup_pass_confirm.clear()
        except Exception as exc:
            self.status_output.append(f"❌ Backup failed: {exc}")
            QMessageBox.critical(self, "Backup Failed", str(exc))

    # ------------------------------------------------------------------
    # Verify backup
    # ------------------------------------------------------------------

    def _verify_backup(self) -> None:
        path = self.restore_path_input.text().strip()
        pw = self.restore_pass_input.text()

        if not path:
            QMessageBox.warning(self, "Verify", "Please specify the backup file path.")
            return
        if not pw:
            QMessageBox.warning(self, "Verify", "Please enter the backup passphrase.")
            return

        try:
            ks = hbz.KeyStore()
            manifest = ks.verify_backup(path, pw.encode())
            info = (
                f"✅ Backup verified successfully.\n"
                f"  Created: {manifest.created_at}\n"
                f"  Label: {manifest.label or '(none)'}\n"
                f"  Private keys: {manifest.private_key_count}\n"
                f"  Public keys: {manifest.public_key_count}\n"
                f"  Contacts: {manifest.contact_count}\n"
                f"  Integrity hash: {manifest.integrity_hash[:24]}…"
            )
            self.status_output.append(info)
        except Exception as exc:
            self.status_output.append(f"❌ Verification failed: {exc}")
            QMessageBox.critical(self, "Verify Failed", str(exc))

    # ------------------------------------------------------------------
    # Restore backup
    # ------------------------------------------------------------------

    def _restore_backup(self) -> None:
        path = self.restore_path_input.text().strip()
        pw = self.restore_pass_input.text()

        if not path:
            QMessageBox.warning(self, "Restore", "Please specify the backup file path.")
            return
        if not pw:
            QMessageBox.warning(self, "Restore", "Please enter the backup passphrase.")
            return

        reply = QMessageBox.question(
            self,
            "Confirm Restore",
            "Restoring a backup will import all keys and contacts.\n"
            "Existing keys with the same fingerprint will NOT be overwritten.\n\n"
            "Continue?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No,
        )
        if reply != QMessageBox.StandardButton.Yes:
            return

        try:
            ks = hbz.KeyStore()
            manifest = ks.restore_backup(path, pw.encode())
            info = (
                f"✅ Backup restored successfully.\n"
                f"  Private keys: {manifest.private_key_count}\n"
                f"  Public keys: {manifest.public_key_count}\n"
                f"  Contacts: {manifest.contact_count}"
            )
            self.status_output.append(info)
            self.restore_pass_input.clear()
        except Exception as exc:
            self.status_output.append(f"❌ Restore failed: {exc}")
            QMessageBox.critical(self, "Restore Failed", str(exc))
