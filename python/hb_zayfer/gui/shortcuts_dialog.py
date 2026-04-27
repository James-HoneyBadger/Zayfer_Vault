"""Keyboard Shortcuts help dialog.

Lists every keyboard shortcut the main window exposes so users can discover
navigation, search, and refresh hotkeys without hunting through menus.
"""

from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtGui import QFont
from PySide6.QtWidgets import (
    QDialog,
    QDialogButtonBox,
    QHeaderView,
    QLabel,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
)

# (Shortcut, Description) pairs grouped logically.
SHORTCUTS: list[tuple[str, str]] = [
    # Application
    ("Ctrl+Q", "Quit Zayfer Vault"),
    ("F1", "Show this Keyboard Shortcuts dialog"),
    # Navigation
    ("Alt+1", "Go to Encrypt"),
    ("Alt+2", "Go to Decrypt"),
    ("Alt+3", "Go to Key Generation"),
    ("Alt+4", "Go to Keyring"),
    ("Alt+5", "Go to Contacts"),
    ("Alt+6", "Go to Sign"),
    ("Alt+7", "Go to Verify"),
    ("Alt+8", "Go to Password Generator"),
    ("Alt+9", "Go to Messaging"),
    ("Alt+0", "Go to Audit Log"),
    # Actions
    ("Ctrl+F", "Focus search box (Keyring / Contacts)"),
    ("Ctrl+R", "Refresh current view (Home / Keyring / Contacts)"),
]


class ShortcutsDialog(QDialog):
    """Modal dialog listing all keyboard shortcuts."""

    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self.setWindowTitle("Keyboard Shortcuts")
        self.setMinimumSize(460, 460)
        self.setAccessibleName("Keyboard Shortcuts dialog")

        layout = QVBoxLayout(self)
        layout.setSpacing(12)
        layout.setContentsMargins(20, 20, 20, 20)

        title = QLabel("Keyboard Shortcuts")
        title_font = QFont()
        title_font.setPointSize(16)
        title_font.setBold(True)
        title.setFont(title_font)
        title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(title)

        table = QTableWidget(len(SHORTCUTS), 2, self)
        table.setHorizontalHeaderLabels(["Shortcut", "Action"])
        table.verticalHeader().setVisible(False)
        table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        table.setSelectionMode(QTableWidget.SelectionMode.SingleSelection)
        table.setAlternatingRowColors(True)
        table.setAccessibleName("Shortcuts table")
        table.setAccessibleDescription(
            "Two-column table listing each keyboard shortcut and the action it performs."
        )

        header = table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)

        for row, (key, desc) in enumerate(SHORTCUTS):
            key_item = QTableWidgetItem(key)
            key_item.setFont(QFont("monospace"))
            desc_item = QTableWidgetItem(desc)
            table.setItem(row, 0, key_item)
            table.setItem(row, 1, desc_item)

        layout.addWidget(table, 1)

        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Close, parent=self)
        buttons.rejected.connect(self.reject)
        buttons.accepted.connect(self.accept)
        # Close button maps to "rejected" by default for StandardButton.Close
        close_btn = buttons.button(QDialogButtonBox.StandardButton.Close)
        if close_btn is not None:
            close_btn.clicked.connect(self.accept)
            close_btn.setAccessibleName("Close shortcuts dialog")
        layout.addWidget(buttons)
