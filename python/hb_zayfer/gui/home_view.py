"""Home dashboard view for the desktop GUI."""

from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QWidget,
    QVBoxLayout,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QGroupBox,
    QGridLayout,
)

import hb_zayfer as hbz


class HomeView(QWidget):
    """Landing page with summary stats and quick actions."""

    def __init__(self, navigate_to) -> None:
        super().__init__()
        self._navigate_to = navigate_to
        self._setup_ui()
        self.refresh()

    def _setup_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 16, 20, 16)
        layout.setSpacing(14)

        title = QLabel("Welcome to Zayfer Vault")
        title.setStyleSheet("font-size: 22px; font-weight: 700;")
        layout.addWidget(title)

        subtitle = QLabel(
            "Manage keys, protect files, and verify activity from one place. "
            "Use the quick actions below to get started."
        )
        subtitle.setWordWrap(True)
        subtitle.setStyleSheet("color: palette(mid);")
        layout.addWidget(subtitle)

        summary_box = QGroupBox("Workspace Summary")
        summary_layout = QGridLayout(summary_box)
        summary_layout.setHorizontalSpacing(24)
        summary_layout.setVerticalSpacing(10)

        self.keys_value = QLabel("—")
        self.contacts_value = QLabel("—")
        self.audit_value = QLabel("—")
        for widget in (self.keys_value, self.contacts_value, self.audit_value):
            widget.setAlignment(Qt.AlignmentFlag.AlignCenter)
            widget.setStyleSheet("font-size: 26px; font-weight: 700;")

        summary_layout.addWidget(QLabel("Keys"), 0, 0)
        summary_layout.addWidget(QLabel("Contacts"), 0, 1)
        summary_layout.addWidget(QLabel("Audit Entries"), 0, 2)
        summary_layout.addWidget(self.keys_value, 1, 0)
        summary_layout.addWidget(self.contacts_value, 1, 1)
        summary_layout.addWidget(self.audit_value, 1, 2)
        layout.addWidget(summary_box)

        actions_box = QGroupBox("Quick Actions")
        actions_layout = QHBoxLayout(actions_box)
        actions_layout.setSpacing(10)

        for label, index in [
            ("Encrypt a File", 1),
            ("Generate a Key", 3),
            ("Open Keyring", 4),
            ("Create Backup", 13),
        ]:
            btn = QPushButton(label)
            btn.clicked.connect(lambda _checked=False, idx=index: self._navigate_to(idx))
            actions_layout.addWidget(btn)

        layout.addWidget(actions_box)

        tips_box = QGroupBox("Recommended First Steps")
        tips_layout = QVBoxLayout(tips_box)
        for text in [
            "1. Generate a personal signing or encryption key pair.",
            "2. Add a contact and link their public key.",
            "3. Encrypt a test file and verify you can decrypt it.",
            "4. Create an encrypted backup of your keystore.",
        ]:
            lbl = QLabel(text)
            lbl.setWordWrap(True)
            tips_layout.addWidget(lbl)
        layout.addWidget(tips_box)

        refresh_row = QHBoxLayout()
        refresh_row.addStretch()
        refresh_btn = QPushButton("Refresh Overview")
        refresh_btn.clicked.connect(self.refresh)
        refresh_row.addWidget(refresh_btn)
        layout.addLayout(refresh_row)
        layout.addStretch()

    def refresh(self) -> None:
        """Refresh key, contact, and audit counts."""
        key_count = 0
        contact_count = 0
        audit_count = 0

        try:
            ks = hbz.KeyStore()
            key_count = len(ks.list_keys())
            contact_count = len(ks.list_contacts())
        except Exception:
            pass

        try:
            audit_count = hbz.AuditLogger().entry_count()
        except Exception:
            pass

        self.keys_value.setText(str(key_count))
        self.contacts_value.setText(str(contact_count))
        self.audit_value.setText(str(audit_count))
