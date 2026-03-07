"""Keyring view — manage stored keys."""

from __future__ import annotations

from pathlib import Path

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QWidget,
    QVBoxLayout,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QHeaderView,
    QMessageBox,
    QFileDialog,
    QAbstractItemView,
)

import hb_zayfer as hbz


class KeyringView(QWidget):
    """Browse and manage keys in the keyring."""

    def __init__(self) -> None:
        super().__init__()
        self._setup_ui()

    def _setup_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 20, 20, 20)

        header = QHBoxLayout()
        header.addWidget(QLabel("<h2>Keyring</h2>"))
        header.addStretch()

        refresh_btn = QPushButton("Refresh")
        refresh_btn.clicked.connect(self.refresh)
        header.addWidget(refresh_btn)

        layout.addLayout(header)

        # Table
        self.table = QTableWidget()
        self.table.setColumnCount(6)
        self.table.setHorizontalHeaderLabels(["Label", "Algorithm", "Fingerprint", "Private", "Public", "Created"])
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.Interactive)
        self.table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.table.setAlternatingRowColors(True)
        layout.addWidget(self.table, 1)

        # Action buttons
        btn_row = QHBoxLayout()
        export_btn = QPushButton("Export Public Key")
        export_btn.clicked.connect(self._export_key)
        btn_row.addWidget(export_btn)

        delete_btn = QPushButton("Delete Key")
        delete_btn.setStyleSheet("QPushButton { color: #ff4444; }")
        delete_btn.clicked.connect(self._delete_key)
        btn_row.addWidget(delete_btn)

        copy_fp_btn = QPushButton("Copy Fingerprint")
        copy_fp_btn.clicked.connect(self._copy_fingerprint)
        btn_row.addWidget(copy_fp_btn)

        btn_row.addStretch()
        layout.addLayout(btn_row)

    def refresh(self) -> None:
        """Reload keys from disk."""
        try:
            ks = hbz.KeyStore()
            keys = ks.list_keys()
        except Exception as e:
            QMessageBox.critical(self, "Error", str(e))
            return

        self.table.setRowCount(len(keys))
        for i, k in enumerate(keys):
            self.table.setItem(i, 0, QTableWidgetItem(k.label))
            self.table.setItem(i, 1, QTableWidgetItem(k.algorithm))
            fp_item = QTableWidgetItem(k.fingerprint)
            fp_item.setToolTip(k.fingerprint)
            self.table.setItem(i, 2, fp_item)
            self.table.setItem(i, 3, QTableWidgetItem("Yes" if k.has_private else "No"))
            self.table.setItem(i, 4, QTableWidgetItem("Yes" if k.has_public else "No"))
            self.table.setItem(i, 5, QTableWidgetItem(k.created_at[:10]))

    def _selected_fingerprint(self) -> str | None:
        row = self.table.currentRow()
        if row < 0:
            QMessageBox.warning(self, "Error", "Select a key first.")
            return None
        fp_item = self.table.item(row, 2)
        return fp_item.text() if fp_item else None

    def _export_key(self) -> None:
        fp = self._selected_fingerprint()
        if not fp:
            return
        path, _ = QFileDialog.getSaveFileName(self, "Export public key", f"{fp[:16]}.pub")
        if not path:
            return
        try:
            ks = hbz.KeyStore()
            pub_data = ks.load_public_key(fp)
            Path(path).write_bytes(pub_data)
            QMessageBox.information(self, "Exported", f"Public key saved to:\n{path}")
        except Exception as e:
            QMessageBox.critical(self, "Error", str(e))

    def _delete_key(self) -> None:
        fp = self._selected_fingerprint()
        if not fp:
            return
        reply = QMessageBox.question(
            self, "Delete Key",
            f"Delete key {fp[:24]}..?\nThis cannot be undone.",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
        )
        if reply != QMessageBox.StandardButton.Yes:
            return
        try:
            ks = hbz.KeyStore()
            ks.delete_key(fp)
            self.refresh()
        except Exception as e:
            QMessageBox.critical(self, "Error", str(e))

    def _copy_fingerprint(self) -> None:
        fp = self._selected_fingerprint()
        if not fp:
            return
        from PySide6.QtWidgets import QApplication
        QApplication.clipboard().setText(fp)
        QMessageBox.information(self, "Copied", "Fingerprint copied to clipboard.")
