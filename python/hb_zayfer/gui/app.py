"""Application entry point and QApplication setup."""

from __future__ import annotations

import sys

from PySide6.QtWidgets import QApplication
from PySide6.QtCore import Qt

from hb_zayfer.gui.main_window import MainWindow


def main() -> None:
    """Launch the HB_Zayfer desktop application."""
    app = QApplication(sys.argv)
    app.setApplicationName("HB_Zayfer")
    app.setOrganizationName("HB_Zayfer")
    app.setApplicationDisplayName("HB_Zayfer Encryption Suite")

    # Modern dark palette
    app.setStyle("Fusion")
    _apply_dark_palette(app)

    window = MainWindow()
    window.show()
    sys.exit(app.exec())


def _apply_dark_palette(app: QApplication) -> None:
    """Apply a dark color palette to the application."""
    from PySide6.QtGui import QPalette, QColor

    palette = QPalette()

    # Base colors
    dark = QColor(30, 30, 30)
    mid_dark = QColor(45, 45, 48)
    mid = QColor(60, 60, 65)
    light = QColor(200, 200, 200)
    accent = QColor(0, 122, 204)     # Blue accent
    highlight = QColor(0, 122, 204)

    palette.setColor(QPalette.ColorRole.Window, mid_dark)
    palette.setColor(QPalette.ColorRole.WindowText, light)
    palette.setColor(QPalette.ColorRole.Base, dark)
    palette.setColor(QPalette.ColorRole.AlternateBase, mid_dark)
    palette.setColor(QPalette.ColorRole.ToolTipBase, mid)
    palette.setColor(QPalette.ColorRole.ToolTipText, light)
    palette.setColor(QPalette.ColorRole.Text, light)
    palette.setColor(QPalette.ColorRole.Button, mid_dark)
    palette.setColor(QPalette.ColorRole.ButtonText, light)
    palette.setColor(QPalette.ColorRole.BrightText, QColor(255, 255, 255))
    palette.setColor(QPalette.ColorRole.Link, accent)
    palette.setColor(QPalette.ColorRole.Highlight, highlight)
    palette.setColor(QPalette.ColorRole.HighlightedText, QColor(255, 255, 255))

    # Disabled
    palette.setColor(QPalette.ColorGroup.Disabled, QPalette.ColorRole.Text, QColor(100, 100, 100))
    palette.setColor(QPalette.ColorGroup.Disabled, QPalette.ColorRole.ButtonText, QColor(100, 100, 100))

    app.setPalette(palette)

    # Stylesheet tweaks
    app.setStyleSheet("""
        QToolTip { color: #c8c8c8; background-color: #3c3c3c; border: 1px solid #555; }
        QGroupBox { border: 1px solid #555; border-radius: 4px; margin-top: 1em; padding-top: 0.6em; }
        QGroupBox::title { subcontrol-origin: margin; left: 10px; padding: 0 3px; }
        QPushButton { padding: 6px 16px; border-radius: 4px; background-color: #3c3c3c; border: 1px solid #555; }
        QPushButton:hover { background-color: #505050; }
        QPushButton:pressed { background-color: #007acc; }
        QPushButton:disabled { background-color: #2d2d30; color: #666; }
        QLineEdit, QTextEdit, QPlainTextEdit, QComboBox { padding: 4px; border: 1px solid #555; border-radius: 3px; background-color: #1e1e1e; }
        QTabWidget::pane { border: 1px solid #555; }
        QProgressBar { border: 1px solid #555; border-radius: 3px; text-align: center; }
        QProgressBar::chunk { background-color: #007acc; }

        /* Sidebar navigation */
        #sidebar {
            background-color: #252526;
            border-right: 1px solid #007acc;
            outline: none;
            font-size: 13px;
        }
        #sidebar::item {
            color: #c8c8c8;
            padding: 8px 12px;
            border-left: 3px solid transparent;
            border-radius: 0;
        }
        #sidebar::item:hover {
            background-color: #2a2d2e;
            color: #ffffff;
            border-left: 3px solid #555;
        }
        #sidebar::item:selected {
            background-color: #37373d;
            color: #ffffff;
            border-left: 3px solid #007acc;
        }
        #sidebar::item:selected:hover {
            background-color: #3c3c42;
        }
    """)


if __name__ == "__main__":
    main()
