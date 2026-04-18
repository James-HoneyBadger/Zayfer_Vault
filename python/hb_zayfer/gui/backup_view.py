"""Backup / Restore view.

This widget is intentionally backed by `CryptoWorker` tasks so long-running
backup, verification, and restore operations do not freeze the main GUI event
loop. The view exposes status messages, an indeterminate progress bar, and a
best-effort cancel button that suppresses late UI updates from in-flight work.
"""

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
        self.thread_pool = QThreadPool.globalInstance()
        self._current_worker: CryptoWorker | None = None
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

        self.create_btn = QPushButton("Create Backup")
        self.create_btn.clicked.connect(self._create_backup)
        create_form.addRow("", self.create_btn)
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
        self.verify_btn = QPushButton("Verify Backup")
        self.verify_btn.setToolTip("Check backup integrity without restoring")
        self.verify_btn.clicked.connect(self._verify_backup)
        btn_row.addWidget(self.verify_btn)

        self.restore_btn = QPushButton("Restore Backup")
        self.restore_btn.setToolTip("Restore keys and contacts from backup")
        self.restore_btn.clicked.connect(self._restore_backup)
        btn_row.addWidget(self.restore_btn)
        restore_form.addRow("", btn_row)

        layout.addWidget(restore_box)

        # ---- Status / result ----
        self.status_output = QTextEdit()
        self.status_output.setReadOnly(True)
        self.status_output.setMaximumHeight(120)
        self.status_output.setPlaceholderText("Status messages will appear here…")
        layout.addWidget(self.status_output)

        self.progress = QProgressBar()
        self.progress.setVisible(False)
        self.progress.setRange(0, 1)
        self.progress.setValue(0)
        layout.addWidget(self.progress)

        self.cancel_btn = QPushButton("Cancel Current Task")
        self.cancel_btn.setEnabled(False)
        self.cancel_btn.clicked.connect(self._cancel_current_task)
        layout.addWidget(self.cancel_btn)

        layout.addStretch()

    # ------------------------------------------------------------------
    # Browse dialogs
    # ------------------------------------------------------------------

    def _browse_backup_path(self) -> None:
        path, _ = QFileDialog.getSaveFileName(
            self,
            "Save Backup As",
            self.backup_path_input.text(),
            "Zayfer Vault Backup (*.hbzf-backup);;All Files (*)",
        )
        if path:
            self.backup_path_input.setText(path)

    def _browse_restore_path(self) -> None:
        path, _ = QFileDialog.getOpenFileName(
            self,
            "Open Backup File",
            str(Path.home()),
            "Zayfer Vault Backup (*.hbzf-backup);;All Files (*)",
        )
        if path:
            self.restore_path_input.setText(path)

    def _append_status(self, message: str) -> None:
        """Append a timestamped status message."""
        self.status_output.append(f"[{datetime.now():%H:%M:%S}] {message}")

    def _set_busy(self, busy: bool, message: str | None = None) -> None:
        """Toggle busy UI state for long-running backup operations."""
        for button in (self.create_btn, self.verify_btn, self.restore_btn):
            button.setEnabled(not busy)
        self.cancel_btn.setEnabled(busy)
        self.progress.setVisible(busy)
        if busy:
            self.progress.setRange(0, 0)
            if message:
                self._append_status(message)
        else:
            self.progress.setRange(0, 1)
            self.progress.setValue(0)

    def _start_worker(self, worker: CryptoWorker, message: str, on_result) -> None:
        """Start a background task with shared progress/error handling.

        All long-running backup operations funnel through this helper so the
        view stays consistent: one task at a time, one busy indicator, and a
        shared completion/error path.
        """
        self._current_worker = worker
        self._set_busy(True, message)
        worker.signals.result.connect(on_result)
        worker.signals.error.connect(self._on_worker_error)
        worker.signals.finished.connect(self._on_worker_finished)
        self.thread_pool.start(worker)

    def _cancel_current_task(self) -> None:
        """Request cancellation of the current background operation."""
        if self._current_worker is None:
            return
        self._current_worker.cancel()
        self._append_status("⚠️ Cancellation requested. Any in-flight work will finish in the background.")
        self._set_busy(False)

    def _on_worker_error(self, error: str) -> None:
        self._append_status(f"❌ Operation failed: {error}")
        QMessageBox.critical(self, "Operation Failed", error)

    def _on_worker_finished(self) -> None:
        self._current_worker = None
        self._set_busy(False)

    @staticmethod
    def _create_backup_work(dest: str, passphrase: bytes, label: str | None):
        ks = hbz.KeyStore()
        ks.create_backup(dest, passphrase, label)
        return dest, ks.verify_backup(dest, passphrase)

    @staticmethod
    def _verify_backup_work(path: str, passphrase: bytes):
        ks = hbz.KeyStore()
        return ks.verify_backup(path, passphrase)

    @staticmethod
    def _restore_backup_work(path: str, passphrase: bytes):
        ks = hbz.KeyStore()
        return ks.restore_backup(path, passphrase)

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

        worker = CryptoWorker(self._create_backup_work, dest, pw.encode(), label)
        self._start_worker(worker, f"Creating backup at {dest}…", self._on_create_backup_done)

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

        worker = CryptoWorker(self._verify_backup_work, path, pw.encode())
        self._start_worker(worker, f"Verifying backup {path}…", self._on_verify_backup_done)

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

        worker = CryptoWorker(self._restore_backup_work, path, pw.encode())
        self._start_worker(worker, f"Restoring backup from {path}…", self._on_restore_backup_done)

    def _on_create_backup_done(self, result: object) -> None:
        dest, manifest = result
        info = (
            f"✅ Backup created: {dest}\n"
            f"  Label: {manifest.label or '(none)'}\n"
            f"  Private keys: {manifest.private_key_count}\n"
            f"  Public keys: {manifest.public_key_count}\n"
            f"  Contacts: {manifest.contact_count}"
        )
        self._append_status(info)
        self.restore_path_input.setText(str(dest))
        self.backup_pass_input.clear()
        self.backup_pass_confirm.clear()

    def _on_verify_backup_done(self, manifest: object) -> None:
        info = (
            f"✅ Backup verified successfully.\n"
            f"  Created: {manifest.created_at}\n"
            f"  Label: {manifest.label or '(none)'}\n"
            f"  Private keys: {manifest.private_key_count}\n"
            f"  Public keys: {manifest.public_key_count}\n"
            f"  Contacts: {manifest.contact_count}\n"
            f"  Integrity hash: {manifest.integrity_hash[:24]}…"
        )
        self._append_status(info)

    def _on_restore_backup_done(self, manifest: object) -> None:
        info = (
            f"✅ Backup restored successfully.\n"
            f"  Private keys: {manifest.private_key_count}\n"
            f"  Public keys: {manifest.public_key_count}\n"
            f"  Contacts: {manifest.contact_count}"
        )
        self._append_status(info)
        self.restore_pass_input.clear()
