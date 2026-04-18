"""Application entry point and QApplication setup."""

from __future__ import annotations

import sys

from PySide6.QtWidgets import QApplication

from hb_zayfer.gui.main_window import MainWindow
from hb_zayfer.gui.settings_view import _load_config
from hb_zayfer.gui.theme import Theme


def main() -> None:
    """Launch the Zayfer Vault desktop application."""
    app = QApplication(sys.argv)
    app.setApplicationName("Zayfer Vault")
    app.setOrganizationName("Honey Badger Universe")
    # Keep displayName empty to prevent GNOME from appending it to window title
    app.setApplicationDisplayName("")

    cfg = _load_config()
    if cfg.get("dark_mode", True):
        Theme.apply_dark_theme(app)
    else:
        Theme.apply_light_theme(app)

    window = MainWindow()
    window.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
