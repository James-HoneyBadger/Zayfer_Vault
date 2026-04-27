"""Main window with sidebar navigation and stacked views.

The main window coordinates persistent settings, notification toasts, the
14-page navigation stack, and the first-run onboarding prompt that helps new
users generate keys or review settings before handling real data.
"""

from __future__ import annotations

import os

from PySide6.QtCore import QSize, Qt, QTimer
from PySide6.QtGui import QAction, QKeySequence
from PySide6.QtWidgets import (
    QHBoxLayout,
    QListWidget,
    QListWidgetItem,
    QMainWindow,
    QMessageBox,
    QStackedWidget,
    QWidget,
)

import hb_zayfer as hbz
from hb_zayfer.gui.about_dialog import AboutDialog
from hb_zayfer.gui.audit_view import AuditView
from hb_zayfer.gui.backup_view import BackupView
from hb_zayfer.gui.contacts_view import ContactsView
from hb_zayfer.gui.decrypt_view import DecryptView
from hb_zayfer.gui.encrypt_view import EncryptView
from hb_zayfer.gui.home_view import HomeView
from hb_zayfer.gui.keygen_view import KeygenView
from hb_zayfer.gui.keyring_view import KeyringView
from hb_zayfer.gui.messaging_view import MessagingView
from hb_zayfer.gui.notifications import NotificationManager
from hb_zayfer.gui.passgen_view import PasswordGenView
from hb_zayfer.gui.qr_view import QRExchangeView
from hb_zayfer.gui.settings_manager import SettingsManager
from hb_zayfer.gui.settings_view import SettingsView
from hb_zayfer.gui.sign_view import SignView
from hb_zayfer.gui.statusbar import StatusBar
from hb_zayfer.gui.verify_view import VerifyView
from hb_zayfer.services import AppInfo, AppPaths


class MainWindow(QMainWindow):
    """Primary application window."""

    def __init__(self) -> None:
        super().__init__()

        # Initialize settings manager
        self.settings = SettingsManager(AppPaths.current().config_dir)

        # Initialize notification manager
        self.notifications = NotificationManager(self)

        self.app_info = AppInfo.current()
        self.setWindowTitle(self.app_info.window_title)
        self.setMinimumSize(900, 600)

        # Restore window geometry from settings
        width = self.settings.get("window.width", 1100)
        height = self.settings.get("window.height", 700)
        self.resize(width, height)

        x = self.settings.get("window.x")
        y = self.settings.get("window.y")
        if x is not None and y is not None:
            self.move(x, y)

        if self.settings.get("window.maximized", False):
            self.showMaximized()

        self._setup_menu()
        self._setup_ui()
        self._setup_statusbar()
        self._setup_shortcuts()
        QTimer.singleShot(0, self._maybe_show_onboarding)

    # ---------------------------------------------------------------
    # Menu bar
    # ---------------------------------------------------------------

    def _setup_menu(self) -> None:
        menu = self.menuBar()

        file_menu = menu.addMenu("&File")
        file_menu.addAction("E&xit", self.close, "Ctrl+Q")

        view_menu = menu.addMenu("&View")
        view_menu.addAction("&Home", lambda: self.sidebar.setCurrentRow(0))
        view_menu.addAction("&Encrypt", lambda: self.sidebar.setCurrentRow(1), "Alt+1")
        view_menu.addAction("&Decrypt", lambda: self.sidebar.setCurrentRow(2), "Alt+2")
        view_menu.addAction("Key &Generation", lambda: self.sidebar.setCurrentRow(3), "Alt+3")
        view_menu.addAction("&Keyring", lambda: self.sidebar.setCurrentRow(4), "Alt+4")
        view_menu.addAction("&Contacts", lambda: self.sidebar.setCurrentRow(5), "Alt+5")
        view_menu.addAction("S&ign", lambda: self.sidebar.setCurrentRow(6), "Alt+6")
        view_menu.addAction("&Verify", lambda: self.sidebar.setCurrentRow(7), "Alt+7")
        view_menu.addAction("&Password Gen", lambda: self.sidebar.setCurrentRow(8), "Alt+8")
        view_menu.addAction("&Messaging", lambda: self.sidebar.setCurrentRow(9), "Alt+9")
        view_menu.addAction("Q&R Exchange", lambda: self.sidebar.setCurrentRow(10))
        view_menu.addAction("&Settings", lambda: self.sidebar.setCurrentRow(11))
        view_menu.addAction("&Audit Log", lambda: self.sidebar.setCurrentRow(12), "Alt+0")
        view_menu.addAction("&Backup", lambda: self.sidebar.setCurrentRow(13))

        help_menu = menu.addMenu("&Help")
        about_action = QAction("&About", self)
        about_action.triggered.connect(self._show_about)
        help_menu.addAction(about_action)

    def _show_about(self) -> None:
        dialog = AboutDialog(self)
        dialog.exec()

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
        self.sidebar.setFixedWidth(180)
        self.sidebar.setIconSize(QSize(18, 18))
        self.sidebar.setSpacing(2)
        self.sidebar.setFocusPolicy(Qt.FocusPolicy.StrongFocus)
        self.sidebar.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)

        pages = [
            ("🏠 Home", "Overview and quick actions"),
            ("🔐 Encrypt", "Encrypt files or text"),
            ("🔓 Decrypt", "Decrypt files or text"),
            ("🔑 Key Gen", "Generate key pairs"),
            ("📦 Keyring", "Manage stored keys"),
            ("👥 Contacts", "Manage contacts"),
            ("✍️ Sign", "Sign files or messages"),
            ("✔️ Verify", "Verify signatures"),
            ("🔐 PassGen", "Password & passphrase generator"),
            ("💬 Messaging", "Secure encrypted messaging"),
            ("📱 QR Exchange", "Share keys via QR codes"),
            ("⚙️ Settings", "Application settings"),
            ("📋 Audit Log", "View audit trail"),
            ("💾 Backup", "Backup & restore keys"),
        ]

        for name, tooltip in pages:
            item = QListWidgetItem(name)
            item.setToolTip(tooltip)
            item.setSizeHint(QSize(178, 38))
            item.setFlags(Qt.ItemFlag.ItemIsSelectable | Qt.ItemFlag.ItemIsEnabled)
            self.sidebar.addItem(item)

        self.sidebar.setCurrentRow(0)
        self.sidebar.currentRowChanged.connect(self._on_page_changed)

        # Stacked widget (views)
        self.stack = QStackedWidget()
        self.home_view = HomeView(self.sidebar.setCurrentRow)
        self.encrypt_view = EncryptView()
        self.decrypt_view = DecryptView()
        self.keygen_view = KeygenView()
        self.keyring_view = KeyringView()
        self.contacts_view = ContactsView()
        self.sign_view = SignView()
        self.verify_view = VerifyView()
        self.passgen_view = PasswordGenView()
        self.messaging_view = MessagingView()
        self.qr_view = QRExchangeView()
        self.settings_view = SettingsView()
        self.audit_view = AuditView()
        self.backup_view = BackupView()

        self.stack.addWidget(self.home_view)
        self.stack.addWidget(self.encrypt_view)
        self.stack.addWidget(self.decrypt_view)
        self.stack.addWidget(self.keygen_view)
        self.stack.addWidget(self.keyring_view)
        self.stack.addWidget(self.contacts_view)
        self.stack.addWidget(self.sign_view)
        self.stack.addWidget(self.verify_view)
        self.stack.addWidget(self.passgen_view)
        self.stack.addWidget(self.messaging_view)
        self.stack.addWidget(self.qr_view)
        self.stack.addWidget(self.settings_view)
        self.stack.addWidget(self.audit_view)
        self.stack.addWidget(self.backup_view)

        layout.addWidget(self.sidebar)
        layout.addWidget(self.stack, 1)

    def _on_page_changed(self, index: int) -> None:
        self.stack.setCurrentIndex(index)
        # Refresh data views when switching and update status bar
        view_names = [
            "Home",
            "Encrypt",
            "Decrypt",
            "Key Generation",
            "Keyring",
            "Contacts",
            "Sign",
            "Verify",
            "Password Gen",
            "Messaging",
            "QR Exchange",
            "Settings",
            "Audit Log",
            "Backup",
        ]
        if index < len(view_names):
            self.status_bar.set_message(f"Viewing: {view_names[index]}")

        if index == 0:  # Home
            self.home_view.refresh()
            self.status_bar.clear_count()
        elif index == 1:  # Encrypt - apply default cipher from settings
            self._apply_settings_to_encrypt()
            self.status_bar.clear_count()
        elif index == 4:  # Keyring
            self.keyring_view.refresh()
            if hasattr(self.keyring_view, "all_keys"):
                self.status_bar.set_count("Keys", len(self.keyring_view.all_keys))
        elif index == 5:  # Contacts
            self.contacts_view.refresh()
            if hasattr(self.contacts_view, "all_contacts"):
                self.status_bar.set_count("Contacts", len(self.contacts_view.all_contacts))
        elif index == 12:  # Audit Log
            self.audit_view.refresh()
            self.status_bar.clear_count()
        else:
            self.status_bar.clear_count()

    def _maybe_show_onboarding(self) -> None:
        """Show a lightweight first-run setup prompt when no keys exist yet."""
        if os.environ.get("HB_ZAYFER_SKIP_ONBOARDING") == "1":
            return
        if self.settings.get("onboarding.seen", False):
            return

        try:
            has_keys = len(hbz.KeyStore().list_keys()) > 0
        except Exception:
            has_keys = False

        if has_keys:
            self.settings.set("onboarding.seen", True)
            self.settings.save()
            return

        box = QMessageBox(self)
        box.setIcon(QMessageBox.Icon.Information)
        box.setWindowTitle("Welcome to Zayfer Vault")
        box.setText("No keys were found yet.")
        box.setInformativeText(
            "Start by generating your first key pair, or review settings before encrypting with a passphrase."
        )
        create_btn = box.addButton("Create First Key", QMessageBox.ButtonRole.AcceptRole)
        settings_btn = box.addButton("Open Settings", QMessageBox.ButtonRole.ActionRole)
        box.addButton("Later", QMessageBox.ButtonRole.RejectRole)
        box.setDefaultButton(create_btn)
        box.exec()

        self.settings.set("onboarding.seen", True)
        self.settings.save()

        if box.clickedButton() == create_btn:
            self.sidebar.setCurrentRow(3)
            self.status_bar.set_message("Welcome — generate your first key pair to get started")
        elif box.clickedButton() == settings_btn:
            self.sidebar.setCurrentRow(11)
            self.status_bar.set_message("Welcome — review your settings before first use")

    # ---------------------------------------------------------------
    # Status bar
    # ---------------------------------------------------------------

    def _setup_statusbar(self) -> None:
        self.status_bar = StatusBar()
        self.setStatusBar(self.status_bar)
        self.status_bar.set_message("Ready")

    # ---------------------------------------------------------------
    # Keyboard Shortcuts
    # ---------------------------------------------------------------

    def _setup_shortcuts(self) -> None:
        """Setup additional keyboard shortcuts."""
        # Ctrl+F for search (when in keyring or contacts)
        search_shortcut = QKeySequence("Ctrl+F")
        search_action = QAction(self)
        search_action.setShortcut(search_shortcut)
        search_action.triggered.connect(self._focus_search)
        self.addAction(search_action)

        # Ctrl+R for refresh
        refresh_shortcut = QKeySequence("Ctrl+R")
        refresh_action = QAction(self)
        refresh_action.setShortcut(refresh_shortcut)
        refresh_action.triggered.connect(self._refresh_current_view)
        self.addAction(refresh_action)

    def _focus_search(self) -> None:
        """Focus search box in current view if available."""
        current_index = self.stack.currentIndex()
        if current_index == 4:  # Keyring
            self.keyring_view.search_input.setFocus()
            self.keyring_view.search_input.selectAll()
        elif current_index == 5:  # Contacts
            self.contacts_view.search_input.setFocus()
            self.contacts_view.search_input.selectAll()

    def _apply_settings_to_encrypt(self) -> None:
        """Apply default cipher from settings to encrypt view."""
        from hb_zayfer.gui.settings_view import _load_config

        cfg = _load_config()
        cipher = cfg.get("cipher", "AES-256-GCM")
        idx = self.encrypt_view.algo_combo.findText(cipher)
        if idx >= 0:
            self.encrypt_view.algo_combo.setCurrentIndex(idx)
        idx2 = self.encrypt_view.text_algo.findText(cipher)
        if idx2 >= 0:
            self.encrypt_view.text_algo.setCurrentIndex(idx2)

    def _refresh_current_view(self) -> None:
        """Refresh current view if supported."""
        current_index = self.stack.currentIndex()
        if current_index == 0:  # Home
            self.home_view.refresh()
            self.notifications.show_info("Overview refreshed")
        elif current_index == 4:  # Keyring
            self.keyring_view.refresh()
            self.notifications.show_info("Keyring refreshed")
        elif current_index == 5:  # Contacts
            self.contacts_view.refresh()
            self.notifications.show_info("Contacts refreshed")

    # ---------------------------------------------------------------
    # Window events
    # ---------------------------------------------------------------

    def closeEvent(self, event) -> None:
        """Save settings before closing."""
        # Save window geometry
        self.settings.set("window.width", self.width())
        self.settings.set("window.height", self.height())
        self.settings.set("window.x", self.x())
        self.settings.set("window.y", self.y())
        self.settings.set("window.maximized", self.isMaximized())

        # Save theme
        from .theme import Theme

        self.settings.set("theme", "dark" if Theme.is_dark_mode() else "light")

        self.settings.save()
        event.accept()
