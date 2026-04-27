"""Keyring view — manage stored keys."""

from __future__ import annotations

from pathlib import Path

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QAbstractItemView,
    QFileDialog,
    QHBoxLayout,
    QHeaderView,
    QInputDialog,
    QLabel,
    QLineEdit,
    QMenu,
    QMessageBox,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

import hb_zayfer as hbz
from hb_zayfer.gui.audit_utils import log_key_deleted
from hb_zayfer.gui.clipboard import secure_copy
from hb_zayfer.gui.theme import Theme


class KeyringView(QWidget):
    """Browse and manage keys in the keyring."""

    def __init__(self) -> None:
        super().__init__()
        self._setup_ui()

    def _setup_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.setContentsMargins(16, 12, 16, 12)
        layout.setSpacing(12)

        header = QHBoxLayout()
        header.addStretch()

        import_btn = QPushButton("Import Key")
        import_btn.clicked.connect(self._import_key)
        header.addWidget(import_btn)

        refresh_btn = QPushButton("Refresh")
        refresh_btn.clicked.connect(self.refresh)
        header.addWidget(refresh_btn)

        layout.addLayout(header)

        # Search box
        search_row = QHBoxLayout()
        search_row.addWidget(QLabel("Search:"))
        self.search_input = QLineEdit()
        self.search_input.setPlaceholderText("Filter by label, algorithm, or fingerprint...")
        self.search_input.textChanged.connect(self._filter_keys)
        search_row.addWidget(self.search_input, 1)
        layout.addLayout(search_row)

        # Table
        self.table = QTableWidget()
        self.table.setColumnCount(6)
        self.table.setHorizontalHeaderLabels(
            ["Label", "Algorithm", "Fingerprint", "Private", "Public", "Created"]
        )
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.Interactive)
        self.table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.table.setAlternatingRowColors(True)
        self.table.setSortingEnabled(True)
        self.table.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.table.customContextMenuRequested.connect(self._show_context_menu)
        layout.addWidget(self.table, 1)

        # Action buttons
        btn_row = QHBoxLayout()
        btn_row.setSpacing(8)
        export_btn = QPushButton("Export Public Key")
        export_btn.setMinimumWidth(120)
        export_btn.clicked.connect(self._export_key)
        btn_row.addWidget(export_btn)

        delete_btn = QPushButton("Delete Key")
        delete_btn.setMinimumWidth(100)
        delete_btn.setStyleSheet(Theme.get_destructive_text_style())
        delete_btn.clicked.connect(self._delete_key)
        btn_row.addWidget(delete_btn)

        copy_fp_btn = QPushButton("Copy Fingerprint")
        copy_fp_btn.setMinimumWidth(120)
        copy_fp_btn.clicked.connect(self._copy_fingerprint)
        btn_row.addWidget(copy_fp_btn)

        btn_row.addStretch()
        layout.addLayout(btn_row)

    def _show_context_menu(self, position) -> None:
        """Show context menu on right-click."""
        if self.table.currentRow() < 0:
            return

        menu = QMenu(self)

        copy_fp_action = menu.addAction("📋 Copy Fingerprint")
        copy_fp_action.triggered.connect(self._copy_fingerprint)

        copy_label_action = menu.addAction("📋 Copy Label")
        copy_label_action.triggered.connect(self._copy_label)

        menu.addSeparator()

        export_action = menu.addAction("💾 Export Public Key...")
        export_action.triggered.connect(self._export_key)

        import_action = menu.addAction("📥 Import Key...")
        import_action.triggered.connect(self._import_key)

        menu.addSeparator()

        delete_action = menu.addAction("🗑️ Delete Key")
        delete_action.triggered.connect(self._delete_key)

        menu.exec(self.table.viewport().mapToGlobal(position))

    def _copy_label(self) -> None:
        """Copy key label to clipboard."""
        row = self.table.currentRow()
        if row < 0:
            return
        label_item = self.table.item(row, 0)
        if label_item:
            secure_copy(label_item.text(), sensitive=False)
            self._notify("show_success", "Label copied to clipboard")

    def refresh(self) -> None:
        """Reload keys from disk."""
        try:
            ks = hbz.KeyStore()
            self.all_keys = ks.list_keys()
        except Exception as e:
            QMessageBox.critical(self, "Error", str(e))
            self.all_keys = []
            return

        self._update_table()

    def _filter_keys(self, search_text: str) -> None:
        """Filter keys based on search text."""
        self._update_table()

    def _update_table(self) -> None:
        """Update table with current filter."""
        search_text = self.search_input.text().lower() if hasattr(self, "search_input") else ""

        if not hasattr(self, "all_keys"):
            self.all_keys = []

        # Filter keys
        if search_text:
            filtered = [
                k
                for k in self.all_keys
                if search_text in k.label.lower()
                or search_text in k.algorithm.lower()
                or search_text in k.fingerprint.lower()
            ]
        else:
            filtered = self.all_keys

        self.table.setRowCount(len(filtered))
        for i, k in enumerate(filtered):
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

            self._notify("show_success", f"Public key exported to {Path(path).name}")
        except Exception as e:
            QMessageBox.critical(self, "Error", str(e))

    def _delete_key(self) -> None:
        fp = self._selected_fingerprint()
        if not fp:
            return

        # Get key details
        try:
            ks = hbz.KeyStore()
            meta = ks.get_key_metadata(fp)
            if not meta:
                QMessageBox.warning(self, "Error", "Key not found.")
                return

            # Check if key is used in contacts
            contacts = ks.list_contacts()
            linked_contacts = [c.name for c in contacts if fp in c.key_fingerprints]

            # Build warning message
            msg = f"<b>Delete key: {meta.label}</b><br>"
            msg += f"<b>Fingerprint:</b> {fp[:32]}...<br>"
            msg += f"<b>Algorithm:</b> {meta.algorithm}<br><br>"

            if linked_contacts:
                msg += f"<b style='color: #dc3545;'>⚠ Warning:</b> This key is linked to {len(linked_contacts)} contact(s):<br>"
                msg += "<ul>" + "".join(f"<li>{c}</li>" for c in linked_contacts[:5])
                if len(linked_contacts) > 5:
                    msg += f"<li>... and {len(linked_contacts) - 5} more</li>"
                msg += "</ul><br>"

            if meta.has_private:
                msg += "<b style='color: #dc3545;'>⚠ This includes the PRIVATE key!</b><br>"
                msg += "If you delete it, you will permanently lose access to:<br>"
                msg += "• Data encrypted to this key<br>"
                msg += "• The ability to sign as this identity<br><br>"
                msg += "Type <b>DELETE</b> to confirm:"

                # Require typed confirmation for private keys
                text, ok = QInputDialog.getText(
                    self, "Confirm Deletion", msg, QLineEdit.EchoMode.Normal, ""
                )
                if not ok or text != "DELETE":
                    return
            else:
                msg += "Type <b>DELETE</b> to confirm:"
                text, ok = QInputDialog.getText(
                    self, "Confirm Deletion", msg, QLineEdit.EchoMode.Normal, ""
                )
                if not ok or text != "DELETE":
                    return

            ks.delete_key(fp)
            log_key_deleted(fp)
            self.refresh()

            self._notify("show_success", f"Key '{meta.label}' deleted")
        except Exception as e:
            QMessageBox.critical(self, "Error", str(e))

    def _copy_fingerprint(self) -> None:
        fp = self._selected_fingerprint()
        if not fp:
            return
        secure_copy(fp)
        self._notify("show_success", "Fingerprint copied to clipboard")

    def _import_key(self) -> None:
        """Import a public key from a file."""
        path, _ = QFileDialog.getOpenFileName(
            self, "Import Public Key", filter="Key files (*.pub *.pem *.asc);;All files (*)"
        )
        if not path:
            return

        try:
            key_data = Path(path).read_bytes()
            key_text = key_data.decode("utf-8", errors="replace")

            # Ask for a label
            from PySide6.QtWidgets import QInputDialog

            label, ok = QInputDialog.getText(
                self,
                "Import Key",
                "Label for imported key:",
                QLineEdit.EchoMode.Normal,
                Path(path).stem,
            )
            if not ok or not label.strip():
                return
            label = label.strip()

            ks = hbz.KeyStore()

            # Detect key type
            if "BEGIN PGP" in key_text:
                fp = hbz.pgp_fingerprint(key_text)
                ks.store_public_key(fp, key_data, "PGP", label)
            elif "BEGIN RSA PUBLIC KEY" in key_text or "BEGIN PUBLIC KEY" in key_text:
                fp = hbz.rsa_fingerprint(key_text)
                ks.store_public_key(fp, key_data, "RSA", label)
            else:
                # Try as raw X25519/Ed25519 (32 bytes)
                if len(key_data) == 32:
                    fp = hbz.x25519_fingerprint(key_data)
                    ks.store_public_key(fp, key_data, "X25519", label)
                else:
                    QMessageBox.warning(self, "Error", "Unrecognized key format.")
                    return

            self.refresh()
            self._notify("show_success", f"Key '{label}' imported successfully")
        except Exception as e:
            QMessageBox.critical(self, "Import Error", str(e))

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
