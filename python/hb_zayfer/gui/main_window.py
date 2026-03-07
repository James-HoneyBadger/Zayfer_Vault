"""Main window with sidebar navigation and stacked views."""

from __future__ import annotations

from PySide6.QtCore import Qt, QSize
from PySide6.QtGui import QIcon, QAction
from PySide6.QtWidgets import (
    QMainWindow,
    QWidget,
    QHBoxLayout,
    QVBoxLayout,
    QListWidget,
    QListWidgetItem,
    QStackedWidget,
    QLabel,
    QStatusBar,
    QMenuBar,
    QMessageBox,
)

from hb_zayfer.gui.encrypt_view import EncryptView
from hb_zayfer.gui.decrypt_view import DecryptView
from hb_zayfer.gui.keygen_view import KeygenView
from hb_zayfer.gui.keyring_view import KeyringView
from hb_zayfer.gui.contacts_view import ContactsView
from hb_zayfer.gui.settings_view import SettingsView
import hb_zayfer as hbz


class MainWindow(QMainWindow):
    """Primary application window."""

    def __init__(self) -> None:
        super().__init__()
        self.setWindowTitle(f"HB_Zayfer Encryption Suite v{hbz.version()}")
        self.setMinimumSize(900, 600)
        self.resize(1100, 700)

        self._setup_menu()
        self._setup_ui()
        self._setup_statusbar()

    # ---------------------------------------------------------------
    # Menu bar
    # ---------------------------------------------------------------

    def _setup_menu(self) -> None:
        menu = self.menuBar()

        file_menu = menu.addMenu("&File")
        file_menu.addAction("E&xit", self.close)

        help_menu = menu.addMenu("&Help")
        about_action = QAction("&About", self)
        about_action.triggered.connect(self._show_about)
        help_menu.addAction(about_action)

    def _show_about(self) -> None:
        QMessageBox.about(
            self,
            "About HB_Zayfer",
            f"<h3>HB_Zayfer Encryption Suite</h3>"
            f"<p>Version {hbz.version()}</p>"
            f"<p>A full-featured encryption/decryption suite powered by Rust.</p>"
            f"<p>Supports AES-256-GCM, ChaCha20-Poly1305, RSA, Ed25519,<br>"
            f"X25519, OpenPGP, Argon2id, and scrypt.</p>",
        )

    # ---------------------------------------------------------------
    # Central UI
    # ---------------------------------------------------------------

    def _setup_ui(self) -> None:
        central = QWidget()
        self.setCentralWidget(central)

        layout = QHBoxLayout(central)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)

        # Sidebar
        self.sidebar = QListWidget()
        self.sidebar.setObjectName("sidebar")
        self.sidebar.setFixedWidth(200)
        self.sidebar.setIconSize(QSize(20, 20))
        self.sidebar.setSpacing(0)
        self.sidebar.setFocusPolicy(Qt.FocusPolicy.StrongFocus)
        self.sidebar.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)

        pages = [
            ("\U0001f510  Encrypt", "Encrypt files or text"),
            ("\U0001f513  Decrypt", "Decrypt files or text"),
            ("\U0001f511  Key Generation", "Generate key pairs"),
            ("\U0001f4e6  Keyring", "Manage stored keys"),
            ("\U0001f465  Contacts", "Manage contacts"),
            ("\u2699\ufe0f  Settings", "Application settings"),
        ]

        for name, tooltip in pages:
            item = QListWidgetItem(name)
            item.setToolTip(tooltip)
            item.setSizeHint(QSize(190, 44))
            item.setFlags(
                Qt.ItemFlag.ItemIsSelectable
                | Qt.ItemFlag.ItemIsEnabled
            )
            self.sidebar.addItem(item)

        self.sidebar.setCurrentRow(0)
        self.sidebar.currentRowChanged.connect(self._on_page_changed)
        self.sidebar.itemClicked.connect(
            lambda item: self._on_page_changed(self.sidebar.row(item))
        )

        # Stacked widget (views)
        self.stack = QStackedWidget()
        self.encrypt_view = EncryptView()
        self.decrypt_view = DecryptView()
        self.keygen_view = KeygenView()
        self.keyring_view = KeyringView()
        self.contacts_view = ContactsView()
        self.settings_view = SettingsView()

        self.stack.addWidget(self.encrypt_view)
        self.stack.addWidget(self.decrypt_view)
        self.stack.addWidget(self.keygen_view)
        self.stack.addWidget(self.keyring_view)
        self.stack.addWidget(self.contacts_view)
        self.stack.addWidget(self.settings_view)

        layout.addWidget(self.sidebar)
        layout.addWidget(self.stack, 1)

    def _on_page_changed(self, index: int) -> None:
        self.stack.setCurrentIndex(index)
        # Refresh data views when switching
        if index == 3:
            self.keyring_view.refresh()
        elif index == 4:
            self.contacts_view.refresh()

    # ---------------------------------------------------------------
    # Status bar
    # ---------------------------------------------------------------

    def _setup_statusbar(self) -> None:
        self.statusBar().showMessage("Ready")
