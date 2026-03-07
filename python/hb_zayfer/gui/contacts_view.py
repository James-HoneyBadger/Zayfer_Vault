"""Contacts view — manage address book."""

from __future__ import annotations

from PySide6.QtCore import Qt
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
    QDialog,
    QDialogButtonBox,
    QFormLayout,
    QAbstractItemView,
)

import hb_zayfer as hbz


class ContactsView(QWidget):
    """Browse and manage contacts."""

    def __init__(self) -> None:
        super().__init__()
        self._setup_ui()

    def _setup_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 20, 20, 20)

        header = QHBoxLayout()
        header.addWidget(QLabel("<h2>Contacts</h2>"))
        header.addStretch()

        add_btn = QPushButton("Add Contact")
        add_btn.clicked.connect(self._add_contact)
        header.addWidget(add_btn)

        refresh_btn = QPushButton("Refresh")
        refresh_btn.clicked.connect(self.refresh)
        header.addWidget(refresh_btn)

        layout.addLayout(header)

        # Table
        self.table = QTableWidget()
        self.table.setColumnCount(4)
        self.table.setHorizontalHeaderLabels(["Name", "Email", "Keys", "Notes"])
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.table.setAlternatingRowColors(True)
        layout.addWidget(self.table, 1)

        # Actions
        btn_row = QHBoxLayout()

        link_btn = QPushButton("Link Key")
        link_btn.clicked.connect(self._link_key)
        btn_row.addWidget(link_btn)

        remove_btn = QPushButton("Remove Contact")
        remove_btn.setStyleSheet("QPushButton { color: #ff4444; }")
        remove_btn.clicked.connect(self._remove_contact)
        btn_row.addWidget(remove_btn)

        btn_row.addStretch()
        layout.addLayout(btn_row)

    def refresh(self) -> None:
        """Reload contacts."""
        try:
            ks = hbz.KeyStore()
            contacts = ks.list_contacts()
        except Exception as e:
            QMessageBox.critical(self, "Error", str(e))
            return

        self.table.setRowCount(len(contacts))
        for i, c in enumerate(contacts):
            self.table.setItem(i, 0, QTableWidgetItem(c.name))
            self.table.setItem(i, 1, QTableWidgetItem(c.email or ""))
            self.table.setItem(i, 2, QTableWidgetItem(str(len(c.key_fingerprints))))
            self.table.setItem(i, 3, QTableWidgetItem(c.notes or ""))

    def _selected_contact_name(self) -> str | None:
        row = self.table.currentRow()
        if row < 0:
            QMessageBox.warning(self, "Error", "Select a contact first.")
            return None
        item = self.table.item(row, 0)
        return item.text() if item else None

    def _add_contact(self) -> None:
        dialog = QDialog(self)
        dialog.setWindowTitle("Add Contact")
        form = QFormLayout(dialog)

        name_input = QLineEdit()
        email_input = QLineEdit()
        notes_input = QLineEdit()

        form.addRow("Name:", name_input)
        form.addRow("Email:", email_input)
        form.addRow("Notes:", notes_input)

        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel)
        buttons.accepted.connect(dialog.accept)
        buttons.rejected.connect(dialog.reject)
        form.addRow(buttons)

        if dialog.exec() == QDialog.DialogCode.Accepted:
            name = name_input.text().strip()
            if not name:
                QMessageBox.warning(self, "Error", "Name is required.")
                return
            email = email_input.text().strip() or None
            notes = notes_input.text().strip() or None
            try:
                ks = hbz.KeyStore()
                ks.add_contact(name, email=email, notes=notes)
                self.refresh()
            except Exception as e:
                QMessageBox.critical(self, "Error", str(e))

    def _link_key(self) -> None:
        name = self._selected_contact_name()
        if not name:
            return

        dialog = QDialog(self)
        dialog.setWindowTitle(f"Link Key to {name}")
        form = QFormLayout(dialog)

        fp_input = QLineEdit()
        fp_input.setPlaceholderText("Fingerprint prefix of the key")
        form.addRow("Fingerprint:", fp_input)

        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel)
        buttons.accepted.connect(dialog.accept)
        buttons.rejected.connect(dialog.reject)
        form.addRow(buttons)

        if dialog.exec() == QDialog.DialogCode.Accepted:
            fp = fp_input.text().strip()
            if not fp:
                return
            try:
                ks = hbz.KeyStore()
                fps = ks.resolve_recipient(fp)
                if fps:
                    fp = fps[0]
                ks.associate_key_with_contact(name, fp)
                self.refresh()
                QMessageBox.information(self, "Success", f"Key linked to {name}.")
            except Exception as e:
                QMessageBox.critical(self, "Error", str(e))

    def _remove_contact(self) -> None:
        name = self._selected_contact_name()
        if not name:
            return
        reply = QMessageBox.question(
            self, "Remove Contact",
            f"Remove contact '{name}'?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
        )
        if reply != QMessageBox.StandardButton.Yes:
            return
        try:
            ks = hbz.KeyStore()
            ks.remove_contact(name)
            self.refresh()
        except Exception as e:
            QMessageBox.critical(self, "Error", str(e))
