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
    QMenu,
    QApplication,
    QComboBox,
)

import hb_zayfer as hbz
from hb_zayfer.gui.clipboard import secure_copy
from hb_zayfer.gui.audit_utils import log_contact_added, log_contact_deleted
from hb_zayfer.gui.theme import Theme


class ContactsView(QWidget):
    """Browse and manage contacts."""

    def __init__(self) -> None:
        super().__init__()
        self._setup_ui()

    def _setup_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.setContentsMargins(16, 12, 16, 12)
        layout.setSpacing(12)

        header = QHBoxLayout()
        header.addStretch()

        add_btn = QPushButton("Add Contact")
        add_btn.clicked.connect(self._add_contact)
        header.addWidget(add_btn)

        refresh_btn = QPushButton("Refresh")
        refresh_btn.clicked.connect(self.refresh)
        header.addWidget(refresh_btn)

        layout.addLayout(header)

        # Search box
        search_row = QHBoxLayout()
        search_row.addWidget(QLabel("Search:"))
        self.search_input = QLineEdit()
        self.search_input.setPlaceholderText("Filter by name, email, or notes...")
        self.search_input.textChanged.connect(self._filter_contacts)
        search_row.addWidget(self.search_input, 1)
        layout.addLayout(search_row)

        # Table
        self.table = QTableWidget()
        self.table.setColumnCount(4)
        self.table.setHorizontalHeaderLabels(["Name", "Email", "Keys", "Notes"])
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.table.setAlternatingRowColors(True)
        self.table.setSortingEnabled(True)
        self.table.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.table.customContextMenuRequested.connect(self._show_context_menu)
        layout.addWidget(self.table, 1)

        # Actions
        btn_row = QHBoxLayout()
        btn_row.setSpacing(8)

        link_btn = QPushButton("Link Key")
        link_btn.setMinimumWidth(100)
        link_btn.clicked.connect(self._link_key)
        btn_row.addWidget(link_btn)

        edit_btn = QPushButton("Edit Contact")
        edit_btn.setMinimumWidth(100)
        edit_btn.clicked.connect(self._edit_contact)
        btn_row.addWidget(edit_btn)

        remove_btn = QPushButton("Remove Contact")
        remove_btn.setMinimumWidth(120)
        remove_btn.setStyleSheet(Theme.get_destructive_text_style())
        remove_btn.clicked.connect(self._remove_contact)
        btn_row.addWidget(remove_btn)

        btn_row.addStretch()
        layout.addLayout(btn_row)

    def _show_context_menu(self, position) -> None:
        """Show context menu on right-click."""
        if self.table.currentRow() < 0:
            return
        
        menu = QMenu(self)
        
        copy_name_action = menu.addAction("📋 Copy Name")
        copy_name_action.triggered.connect(self._copy_name)
        
        copy_email_action = menu.addAction("📋 Copy Email")
        copy_email_action.triggered.connect(self._copy_email)
        
        menu.addSeparator()
        
        edit_action = menu.addAction("✏️ Edit Contact...")
        edit_action.triggered.connect(self._edit_contact)
        
        link_action = menu.addAction("🔗 Link Key...")
        link_action.triggered.connect(self._link_key)
        
        menu.addSeparator()
        
        remove_action = menu.addAction("🗑️ Remove Contact")
        remove_action.triggered.connect(self._remove_contact)
        
        menu.exec(self.table.viewport().mapToGlobal(position))
    
    def _copy_name(self) -> None:
        """Copy contact name to clipboard."""
        row = self.table.currentRow()
        if row < 0:
            return
        name_item = self.table.item(row, 0)
        if name_item:
            secure_copy(name_item.text(), sensitive=False)
            self._notify("show_success", "Name copied to clipboard")
    
    def _copy_email(self) -> None:
        """Copy contact email to clipboard."""
        row = self.table.currentRow()
        if row < 0:
            return
        email_item = self.table.item(row, 1)
        if email_item:
            secure_copy(email_item.text(), sensitive=False)
            self._notify("show_success", "Email copied to clipboard")

    def refresh(self) -> None:
        """Reload contacts."""
        try:
            ks = hbz.KeyStore()
            self.all_contacts = ks.list_contacts()
        except Exception as e:
            QMessageBox.critical(self, "Error", str(e))
            self.all_contacts = []
            return
        
        self._update_table()

    def _filter_contacts(self, search_text: str) -> None:
        """Filter contacts based on search text."""
        self._update_table()

    def _update_table(self) -> None:
        """Update table with current filter."""
        search_text = self.search_input.text().lower() if hasattr(self, 'search_input') else ""
        
        if not hasattr(self, 'all_contacts'):
            self.all_contacts = []
        
        # Filter contacts
        if search_text:
            filtered = [c for c in self.all_contacts 
                       if search_text in c.name.lower() 
                       or (c.email and search_text in c.email.lower())
                       or (c.notes and search_text in c.notes.lower())]
        else:
            filtered = self.all_contacts

        self.table.setRowCount(len(filtered))
        for i, c in enumerate(filtered):
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
                log_contact_added(name)
                self.refresh()
            except Exception as e:
                QMessageBox.critical(self, "Error", str(e))

    def _link_key(self) -> None:
        name = self._selected_contact_name()
        if not name:
            return

        dialog = QDialog(self)
        dialog.setWindowTitle(f"Link Key to {name}")
        dialog.setMinimumWidth(400)
        form = QFormLayout(dialog)

        key_combo = QComboBox()
        key_combo.setMinimumWidth(350)
        try:
            ks = hbz.KeyStore()
            keys = ks.list_keys()
            if not keys:
                key_combo.addItem("No keys available")
            else:
                for k in keys:
                    fp_short = k.fingerprint[:16]
                    key_combo.addItem(f"{k.label} ({k.algorithm}) — {fp_short}...", k.fingerprint)
        except Exception:
            key_combo.addItem("Error loading keys")
        form.addRow("Key:", key_combo)

        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel)
        buttons.accepted.connect(dialog.accept)
        buttons.rejected.connect(dialog.reject)
        form.addRow(buttons)

        if dialog.exec() == QDialog.DialogCode.Accepted:
            fp = key_combo.currentData()
            if not fp:
                return
            try:
                ks = hbz.KeyStore()
                ks.associate_key_with_contact(name, fp)
                self.refresh()
                self._notify("show_success", f"Key linked to {name}")
            except Exception as e:
                QMessageBox.critical(self, "Error", str(e))

    def _remove_contact(self) -> None:
        name = self._selected_contact_name()
        if not name:
            return
        
        # Get contact details
        try:
            ks = hbz.KeyStore()
            contact = ks.get_contact(name)
            if not contact:
                QMessageBox.warning(self, "Error", "Contact not found.")
                return
            
            # Build detailed message
            msg = f"<b>Remove contact: {contact.name}</b><br>"
            if contact.email:
                msg += f"<b>Email:</b> {contact.email}<br>"
            if contact.key_fingerprints:
                msg += f"<b>Linked keys:</b> {len(contact.key_fingerprints)}<br>"
            if contact.notes:
                msg += f"<b>Notes:</b> {contact.notes[:100]}...<br>" if len(contact.notes) > 100 else f"<b>Notes:</b> {contact.notes}<br>"
            msg += "<br><b>Note:</b> This only removes the contact entry. Associated keys remain in your keyring."
            
            reply = QMessageBox.question(
                self, "Remove Contact", msg,
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            )
            if reply != QMessageBox.StandardButton.Yes:
                return
            
            ks.remove_contact(name)
            log_contact_deleted(name)
            self.refresh()
            
            self._notify("show_success", f"Contact '{name}' removed")
        except Exception as e:
            QMessageBox.critical(self, "Error", str(e))

    def _edit_contact(self) -> None:
        """Edit the selected contact."""
        name = self._selected_contact_name()
        if not name:
            return
        try:
            ks = hbz.KeyStore()
            contact = ks.get_contact(name)
            if not contact:
                QMessageBox.warning(self, "Error", "Contact not found.")
                return

            dialog = QDialog(self)
            dialog.setWindowTitle(f"Edit Contact: {name}")
            form = QFormLayout(dialog)

            email_input = QLineEdit(contact.email or "")
            notes_input = QLineEdit(contact.notes or "")

            form.addRow("Name:", QLabel(name))
            form.addRow("Email:", email_input)
            form.addRow("Notes:", notes_input)

            buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel)
            buttons.accepted.connect(dialog.accept)
            buttons.rejected.connect(dialog.reject)
            form.addRow(buttons)

            if dialog.exec() == QDialog.DialogCode.Accepted:
                email = email_input.text().strip() or None
                notes = notes_input.text().strip() or None
                ks.update_contact(name, email=email, notes=notes)
                self.refresh()
                self._notify("show_success", f"Contact '{name}' updated")
        except Exception as e:
            QMessageBox.critical(self, "Error", str(e))

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
