"""Audit Log viewer — browse, verify, and export the audit trail."""

from __future__ import annotations

from pathlib import Path

from PySide6.QtCore import Qt, QThreadPool
from PySide6.QtWidgets import (
    QWidget,
    QVBoxLayout,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QHeaderView,
    QMessageBox,
    QFileDialog,
    QAbstractItemView,
    QSpinBox,
    QComboBox,
)

import hb_zayfer as hbz
from hb_zayfer.gui.workers import CryptoWorker


# Map operation debug strings to friendly labels
_OP_LABELS = {
    "KeyGenerated": "Key Generated",
    "KeyImported": "Key Imported",
    "KeyExported": "Key Exported",
    "KeyDeleted": "Key Deleted",
    "FileEncrypted": "File Encrypted",
    "FileDecrypted": "File Decrypted",
    "DataSigned": "Data Signed",
    "SignatureVerified": "Signature Verified",
    "ContactAdded": "Contact Added",
    "ContactDeleted": "Contact Deleted",
    "BackupCreated": "Backup Created",
    "BackupRestored": "Backup Restored",
    "ConfigModified": "Config Modified",
}


def _friendly_operation(raw: str) -> tuple[str, str]:
    """Return (label, details) from an operation debug string.

    The Rust binding formats the operation as e.g.
    ``KeyGenerated { algorithm: "Ed25519", fingerprint: "abc" }``
    """
    for key, label in _OP_LABELS.items():
        if raw.startswith(key):
            details = raw[len(key):].strip().strip("{}").strip()
            return label, details
    return raw, ""


class AuditView(QWidget):
    """Browse and manage the cryptographic audit trail."""

    def __init__(self) -> None:
        super().__init__()
        self._all_entries: list[object] = []
        self._setup_ui()

    # ------------------------------------------------------------------
    # UI setup
    # ------------------------------------------------------------------

    def _setup_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.setContentsMargins(16, 12, 16, 12)
        layout.setSpacing(12)

        # Header row: title + action buttons
        header = QHBoxLayout()
        title = QLabel("Audit Log")
        title.setStyleSheet("font-size: 16px; font-weight: bold;")
        header.addWidget(title)
        header.addStretch()

        self.entry_count_label = QLabel("")
        header.addWidget(self.entry_count_label)

        verify_btn = QPushButton("Verify Integrity")
        verify_btn.setToolTip("Verify the hash-chain integrity of the audit log")
        verify_btn.clicked.connect(self._verify_integrity)
        header.addWidget(verify_btn)

        export_btn = QPushButton("Export…")
        export_btn.setToolTip("Export audit log to a file")
        export_btn.clicked.connect(self._export_log)
        header.addWidget(export_btn)

        refresh_btn = QPushButton("Refresh")
        refresh_btn.clicked.connect(self.refresh)
        header.addWidget(refresh_btn)

        layout.addLayout(header)

        # Filter / limit row
        filter_row = QHBoxLayout()

        filter_row.addWidget(QLabel("Search:"))
        self.search_input = QLineEdit()
        self.search_input.setPlaceholderText("Filter by operation, details, or note…")
        self.search_input.textChanged.connect(self._apply_filter)
        filter_row.addWidget(self.search_input, 1)

        filter_row.addWidget(QLabel("Show:"))
        self.limit_spin = QSpinBox()
        self.limit_spin.setRange(10, 10000)
        self.limit_spin.setValue(100)
        self.limit_spin.setSuffix(" entries")
        self.limit_spin.setToolTip("Number of recent entries to load")
        filter_row.addWidget(self.limit_spin)

        filter_row.addWidget(QLabel("Operation:"))
        self.op_filter = QComboBox()
        self.op_filter.addItem("All")
        for label in _OP_LABELS.values():
            self.op_filter.addItem(label)
        self.op_filter.currentTextChanged.connect(self._apply_filter)
        filter_row.addWidget(self.op_filter)

        layout.addLayout(filter_row)

        # Table
        self.table = QTableWidget()
        self.table.setColumnCount(5)
        self.table.setHorizontalHeaderLabels(
            ["Timestamp", "Operation", "Details", "Note", "Entry Hash"]
        )
        hdr = self.table.horizontalHeader()
        hdr.setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        hdr.setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        hdr.setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)
        hdr.setSectionResizeMode(3, QHeaderView.ResizeMode.Stretch)
        hdr.setSectionResizeMode(4, QHeaderView.ResizeMode.Interactive)
        self.table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.table.setAlternatingRowColors(True)
        self.table.setSortingEnabled(True)
        layout.addWidget(self.table, 1)

    # ------------------------------------------------------------------
    # Data loading
    # ------------------------------------------------------------------

    def refresh(self) -> None:
        """Reload entries from the audit log."""
        try:
            logger = hbz.AuditLogger()
            count = logger.entry_count()
            self.entry_count_label.setText(f"{count} total entries")
            entries = logger.recent_entries(self.limit_spin.value())
            self._all_entries = entries
            self._apply_filter()
        except Exception as exc:
            self.entry_count_label.setText("Error loading log")
            QMessageBox.warning(self, "Audit Log", f"Failed to load audit log:\n{exc}")

    def _apply_filter(self) -> None:
        """Filter displayed rows by search text and operation type."""
        search = self.search_input.text().lower()
        op_filter = self.op_filter.currentText()

        filtered = []
        for entry in self._all_entries:
            label, details = _friendly_operation(entry.operation)
            if op_filter != "All" and label != op_filter:
                continue
            haystack = f"{label} {details} {entry.note or ''}".lower()
            if search and search not in haystack:
                continue
            filtered.append((entry, label, details))

        self._populate_table(filtered)

    def _populate_table(self, rows: list) -> None:
        """Fill table with filtered entry rows."""
        self.table.setSortingEnabled(False)
        self.table.setRowCount(len(rows))
        for i, (entry, label, details) in enumerate(rows):
            ts_item = QTableWidgetItem(entry.timestamp)
            ts_item.setData(Qt.ItemDataRole.UserRole, entry.timestamp)
            self.table.setItem(i, 0, ts_item)
            self.table.setItem(i, 1, QTableWidgetItem(label))
            self.table.setItem(i, 2, QTableWidgetItem(details))
            self.table.setItem(i, 3, QTableWidgetItem(entry.note or ""))
            hash_item = QTableWidgetItem(entry.entry_hash[:16] + "…")
            hash_item.setToolTip(entry.entry_hash)
            self.table.setItem(i, 4, hash_item)
        self.table.setSortingEnabled(True)

    # ------------------------------------------------------------------
    # Actions
    # ------------------------------------------------------------------

    def _verify_integrity(self) -> None:
        """Verify audit log hash-chain integrity in a background thread."""
        try:
            logger = hbz.AuditLogger()
            valid = logger.verify_integrity()
            if valid:
                QMessageBox.information(
                    self,
                    "Integrity Check",
                    "✅ Audit log integrity verified — hash chain is intact.",
                )
            else:
                QMessageBox.warning(
                    self,
                    "Integrity Check",
                    "⚠️ Audit log integrity check FAILED.\n\n"
                    "The hash chain has been broken, which may indicate "
                    "tampering or corruption.",
                )
        except Exception as exc:
            QMessageBox.critical(
                self, "Integrity Check", f"Error verifying integrity:\n{exc}"
            )

    def _export_log(self) -> None:
        """Export audit log to a user-chosen file."""
        path, _ = QFileDialog.getSaveFileName(
            self,
            "Export Audit Log",
            str(Path.home() / "audit_export.jsonl"),
            "JSON Lines (*.jsonl);;All Files (*)",
        )
        if not path:
            return
        try:
            logger = hbz.AuditLogger()
            logger.export(path)
            QMessageBox.information(
                self, "Export Complete", f"Audit log exported to:\n{path}"
            )
        except Exception as exc:
            QMessageBox.critical(
                self, "Export Failed", f"Failed to export audit log:\n{exc}"
            )
