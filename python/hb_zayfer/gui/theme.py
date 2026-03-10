"""Theme management for GUI - light and dark modes."""

from __future__ import annotations

from PySide6.QtWidgets import QApplication
from PySide6.QtGui import QPalette, QColor
from PySide6.QtCore import Qt


class Theme:
    """Theme manager for light and dark modes."""
    
    _dark_mode: bool = True  # Cached dark mode state
    
    @staticmethod
    def apply_light_theme(app: QApplication) -> None:
        """Apply light theme colors."""
        Theme._dark_mode = False
        app.setStyle("Fusion")
        palette = QPalette()
        
        # Light theme colors with improved contrast
        palette.setColor(QPalette.ColorRole.Window, QColor(245, 245, 245))
        palette.setColor(QPalette.ColorRole.WindowText, QColor(32, 32, 32))
        palette.setColor(QPalette.ColorRole.Base, QColor(255, 255, 255))
        palette.setColor(QPalette.ColorRole.AlternateBase, QColor(248, 248, 248))
        palette.setColor(QPalette.ColorRole.ToolTipBase, QColor(255, 255, 220))
        palette.setColor(QPalette.ColorRole.ToolTipText, QColor(32, 32, 32))
        palette.setColor(QPalette.ColorRole.Text, QColor(32, 32, 32))
        palette.setColor(QPalette.ColorRole.Button, QColor(240, 240, 240))
        palette.setColor(QPalette.ColorRole.ButtonText, QColor(32, 32, 32))
        palette.setColor(QPalette.ColorRole.BrightText, QColor(220, 0, 0))
        palette.setColor(QPalette.ColorRole.Link, QColor(0, 102, 204))
        palette.setColor(QPalette.ColorRole.Highlight, QColor(0, 120, 215))
        palette.setColor(QPalette.ColorRole.HighlightedText, QColor(255, 255, 255))
        
        # Disabled colors for better accessibility
        palette.setColor(QPalette.ColorGroup.Disabled, QPalette.ColorRole.WindowText, QColor(150, 150, 150))
        palette.setColor(QPalette.ColorGroup.Disabled, QPalette.ColorRole.Text, QColor(150, 150, 150))
        palette.setColor(QPalette.ColorGroup.Disabled, QPalette.ColorRole.ButtonText, QColor(150, 150, 150))
        palette.setColor(QPalette.ColorGroup.Disabled, QPalette.ColorRole.Highlight, QColor(200, 200, 200))
        palette.setColor(QPalette.ColorGroup.Disabled, QPalette.ColorRole.HighlightedText, QColor(150, 150, 150))
        
        app.setPalette(palette)
        
        # Comprehensive stylesheet for light mode
        app.setStyleSheet("""
            QToolTip {
                color: #202020;
                background-color: #ffffdc;
                border: 1px solid #c0c0c0;
                padding: 3px;
            }
            QGroupBox {
                border: 1px solid #c0c0c0;
                border-radius: 6px;
                margin-top: 0.8em;
                font-weight: 600;
                font-size: 13px;
                color: #404040;
                padding-top: 8px;
                background-color: #fafafa;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                left: 12px;
                padding: 0 6px 0 6px;
                background-color: #f5f5f5;
            }
            QLineEdit, QTextEdit, QPlainTextEdit {
                background-color: #ffffff;
                color: #202020;
                border: 1px solid #c0c0c0;
                border-radius: 3px;
                padding: 5px;
                selection-background-color: #0078d7;
                selection-color: #ffffff;
            }
            QLineEdit:focus, QTextEdit:focus, QPlainTextEdit:focus {
                border: 1px solid #0078d7;
                border-width: 2px;
            }
            QLineEdit:disabled, QTextEdit:disabled, QPlainTextEdit:disabled {
                background-color: #f5f5f5;
                color: #969696;
            }
            QPushButton {
                background-color: #f0f0f0;
                color: #202020;
                border: 1px solid #c0c0c0;
                border-radius: 3px;
                padding: 5px 15px;
            }
            QPushButton:hover {
                background-color: #e5f3ff;
                border: 1px solid #0078d7;
            }
            QPushButton:pressed {
                background-color: #cce4f7;
            }
            QPushButton:disabled {
                background-color: #f5f5f5;
                color: #969696;
            }
            QComboBox {
                background-color: #ffffff;
                color: #202020;
                border: 1px solid #c0c0c0;
                border-radius: 3px;
                padding: 5px;
                min-height: 20px;
            }
            QComboBox:hover {
                border: 1px solid #0078d7;
            }
            QComboBox:disabled {
                background-color: #f5f5f5;
                color: #969696;
            }
            QComboBox::drop-down {
                border: none;
                width: 20px;
            }
            QComboBox::down-arrow {
                image: none;
                border-left: 4px solid transparent;
                border-right: 4px solid transparent;
                border-top: 5px solid #606060;
                margin-right: 7px;
            }
            QComboBox QAbstractItemView {
                background-color: #ffffff;
                color: #202020;
                border: 1px solid #c0c0c0;
                selection-background-color: #0078d7;
                selection-color: #ffffff;
            }
            QProgressBar {
                border: 1px solid #c0c0c0;
                border-radius: 3px;
                text-align: center;
                background-color: #ffffff;
                color: #202020;
            }
            QProgressBar::chunk {
                background-color: #0078d7;
            }
            QTabWidget::pane {
                border: 1px solid #c0c0c0;
                border-radius: 3px;
                background-color: #ffffff;
            }
            QTabBar::tab {
                background-color: #f0f0f0;
                color: #202020;
                border: 1px solid #c0c0c0;
                border-bottom: none;
                border-top-left-radius: 3px;
                border-top-right-radius: 3px;
                padding: 5px 10px;
                margin-right: 2px;
            }
            QTabBar::tab:selected {
                background-color: #ffffff;
                border-bottom: 2px solid #0078d7;
            }
            QTabBar::tab:hover {
                background-color: #e5f3ff;
            }
            QScrollBar:vertical {
                background-color: #f5f5f5;
                width: 12px;
                margin: 0px;
            }
            QScrollBar::handle:vertical {
                background-color: #c0c0c0;
                min-height: 20px;
                border-radius: 6px;
            }
            QScrollBar::handle:vertical:hover {
                background-color: #a0a0a0;
            }
            QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {
                height: 0px;
            }
            QScrollBar:horizontal {
                background-color: #f5f5f5;
                height: 12px;
                margin: 0px;
            }
            QScrollBar::handle:horizontal {
                background-color: #c0c0c0;
                min-width: 20px;
                border-radius: 6px;
            }
            QScrollBar::handle:horizontal:hover {
                background-color: #a0a0a0;
            }
            QScrollBar::add-line:horizontal, QScrollBar::sub-line:horizontal {
                width: 0px;
            }
            QListWidget, QTreeWidget, QTableWidget {
                background-color: #ffffff;
                color: #202020;
                border: 1px solid #c0c0c0;
                selection-background-color: #0078d7;
                selection-color: #ffffff;
            }
            QListWidget::item:hover, QTreeWidget::item:hover {
                background-color: #e5f3ff;
            }
            QCheckBox, QRadioButton {
                color: #202020;
            }
            QCheckBox:disabled, QRadioButton:disabled {
                color: #969696;
            }
            QLabel {
                color: #202020;
            }
            QSpinBox, QDoubleSpinBox {
                background-color: #ffffff;
                color: #202020;
                border: 1px solid #c0c0c0;
                border-radius: 3px;
                padding: 3px;
            }
            QSpinBox:focus, QDoubleSpinBox:focus {
                border: 1px solid #0078d7;
            }
            QSpinBox:disabled, QDoubleSpinBox:disabled {
                background-color: #f5f5f5;
                color: #969696;
            }
            QListWidget#sidebar {
                background-color: #fafafa;
                border: none;
                border-right: 1px solid #d0d0d0;
                font-size: 13px;
            }
            QListWidget#sidebar::item {
                padding: 8px 12px;
                border-radius: 4px;
                margin: 2px 4px;
            }
            QListWidget#sidebar::item:hover {
                background-color: #e5f3ff;
            }
            QListWidget#sidebar::item:selected {
                background-color: #0078d7;
                color: #ffffff;
            }
        """)
    
    @staticmethod
    def apply_dark_theme(app: QApplication) -> None:
        """Apply dark theme colors."""
        Theme._dark_mode = True
        app.setStyle("Fusion")
        palette = QPalette()
        
        # Dark theme colors
        palette.setColor(QPalette.ColorRole.Window, QColor(53, 53, 53))
        palette.setColor(QPalette.ColorRole.WindowText, QColor(255, 255, 255))
        palette.setColor(QPalette.ColorRole.Base, QColor(35, 35, 35))
        palette.setColor(QPalette.ColorRole.AlternateBase, QColor(45, 45, 45))
        palette.setColor(QPalette.ColorRole.ToolTipBase, QColor(53, 53, 53))
        palette.setColor(QPalette.ColorRole.ToolTipText, QColor(255, 255, 255))
        palette.setColor(QPalette.ColorRole.Text, QColor(255, 255, 255))
        palette.setColor(QPalette.ColorRole.Button, QColor(53, 53, 53))
        palette.setColor(QPalette.ColorRole.ButtonText, QColor(255, 255, 255))
        palette.setColor(QPalette.ColorRole.BrightText, QColor(255, 0, 0))
        palette.setColor(QPalette.ColorRole.Link, QColor(42, 130, 218))
        palette.setColor(QPalette.ColorRole.Highlight, QColor(42, 130, 218))
        palette.setColor(QPalette.ColorRole.HighlightedText, QColor(0, 0, 0))
        
        # Disabled colors
        palette.setColor(QPalette.ColorGroup.Disabled, QPalette.ColorRole.WindowText, QColor(127, 127, 127))
        palette.setColor(QPalette.ColorGroup.Disabled, QPalette.ColorRole.Text, QColor(127, 127, 127))
        palette.setColor(QPalette.ColorGroup.Disabled, QPalette.ColorRole.ButtonText, QColor(127, 127, 127))
        palette.setColor(QPalette.ColorGroup.Disabled, QPalette.ColorRole.Highlight, QColor(80, 80, 80))
        palette.setColor(QPalette.ColorGroup.Disabled, QPalette.ColorRole.HighlightedText, QColor(127, 127, 127))
        
        app.setPalette(palette)
        
        # Additional stylesheet for better dark mode appearance
        app.setStyleSheet("""
            QToolTip {
                color: #ffffff;
                background-color: #2a2a2a;
                border: 1px solid #555555;
            }
            QGroupBox {
                border: 1px solid #555555;
                border-radius: 6px;
                margin-top: 0.8em;
                font-weight: 600;
                font-size: 13px;
                padding-top: 8px;
                background-color: #2a2a2a;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                left: 12px;
                padding: 0 6px 0 6px;
                background-color: #353535;
            }
            QLineEdit, QTextEdit, QPlainTextEdit {
                background-color: #2a2a2a;
                border: 1px solid #555555;
                border-radius: 3px;
                padding: 5px;
                selection-background-color: #2a7acc;
            }
            QLineEdit:focus, QTextEdit:focus, QPlainTextEdit:focus {
                border: 1px solid #007acc;
            }
            QPushButton {
                background-color: #454545;
                border: 1px solid #555555;
                border-radius: 3px;
                padding: 5px 15px;
            }
            QPushButton:hover {
                background-color: #505050;
                border: 1px solid #007acc;
            }
            QPushButton:pressed {
                background-color: #3a3a3a;
            }
            QComboBox {
                background-color: #454545;
                border: 1px solid #555555;
                border-radius: 3px;
                padding: 5px;
            }
            QComboBox:hover {
                border: 1px solid #007acc;
            }
            QComboBox::drop-down {
                border: none;
            }
            QComboBox::down-arrow {
                image: none;
                border-left: 5px solid transparent;
                border-right: 5px solid transparent;
                border-top: 5px solid #aaaaaa;
                margin-right: 5px;
            }
            QProgressBar {
                border: 1px solid #555555;
                border-radius: 3px;
                text-align: center;
                background-color: #2a2a2a;
            }
            QProgressBar::chunk {
                background-color: #007acc;
            }
            QTabWidget::pane {
                border: 1px solid #555555;
                border-radius: 3px;
            }
            QTabBar::tab {
                background-color: #454545;
                border: 1px solid #555555;
                border-bottom: none;
                border-top-left-radius: 3px;
                border-top-right-radius: 3px;
                padding: 5px 10px;
                margin-right: 2px;
            }
            QTabBar::tab:selected {
                background-color: #353535;
                border-bottom: 2px solid #007acc;
            }
            QTabBar::tab:hover {
                background-color: #505050;
            }
            QScrollBar:vertical {
                background-color: #2a2a2a;
                width: 12px;
                margin: 0px;
            }
            QScrollBar::handle:vertical {
                background-color: #555555;
                min-height: 20px;
                border-radius: 6px;
            }
            QScrollBar::handle:vertical:hover {
                background-color: #666666;
            }
            QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {
                height: 0px;
            }
            QScrollBar:horizontal {
                background-color: #2a2a2a;
                height: 12px;
                margin: 0px;
            }
            QScrollBar::handle:horizontal {
                background-color: #555555;
                min-width: 20px;
                border-radius: 6px;
            }
            QScrollBar::handle:horizontal:hover {
                background-color: #666666;
            }
            QScrollBar::add-line:horizontal, QScrollBar::sub-line:horizontal {
                width: 0px;
            }
            QListWidget#sidebar {
                background-color: #2d2d2d;
                border: none;
                border-right: 1px solid #404040;
                font-size: 13px;
            }
            QListWidget#sidebar::item {
                padding: 8px 12px;
                border-radius: 4px;
                margin: 2px 4px;
            }
            QListWidget#sidebar::item:hover {
                background-color: #3d3d3d;
            }
            QListWidget#sidebar::item:selected {
                background-color: #007acc;
                color: #ffffff;
            }
        """)
    
    @staticmethod
    def get_button_style(color: str = "#007acc", dark_mode: bool = False) -> str:
        """Get styled button CSS for primary action buttons."""
        if dark_mode:
            return f"""
                QPushButton {{
                    background-color: {color};
                    color: white;
                    font-weight: bold;
                    font-size: 14px;
                    padding: 10px;
                    border: none;
                    border-radius: 4px;
                }}
                QPushButton:hover {{
                    background-color: {Theme._adjust_color(color, 1.2)};
                }}
                QPushButton:pressed {{
                    background-color: {Theme._adjust_color(color, 0.8)};
                }}
                QPushButton:disabled {{
                    background-color: #555555;
                    color: #888888;
                }}
            """
        else:
            return f"""
                QPushButton {{
                    background-color: {color};
                    color: white;
                    font-weight: bold;
                    font-size: 14px;
                    padding: 10px;
                    border: none;
                    border-radius: 4px;
                }}
                QPushButton:hover {{
                    background-color: {Theme._adjust_color(color, 1.15)};
                }}
                QPushButton:pressed {{
                    background-color: {Theme._adjust_color(color, 0.85)};
                }}
                QPushButton:disabled {{
                    background-color: #cccccc;
                    color: #888888;
                }}
            """
    
    @staticmethod
    def _adjust_color(hex_color: str, factor: float) -> str:
        """Adjust hex color brightness by factor."""
        # Remove '#' if present
        hex_color = hex_color.lstrip('#')
        
        # Convert to RGB
        r = int(hex_color[0:2], 16)
        g = int(hex_color[2:4], 16)
        b = int(hex_color[4:6], 16)
        
        # Adjust
        r = min(255, max(0, int(r * factor)))
        g = min(255, max(0, int(g * factor)))
        b = min(255, max(0, int(b * factor)))
        
        # Convert back to hex
        return f"#{r:02x}{g:02x}{b:02x}"
    
    @staticmethod
    def is_dark_mode() -> bool:
        """Check if dark mode is currently active (cached, no disk reads)."""
        return Theme._dark_mode
    
    @staticmethod
    def get_primary_button_style() -> str:
        """Get primary action button style (blue)."""
        dark = Theme.is_dark_mode()
        return Theme.get_button_style("#0078d7", dark)
    
    @staticmethod
    def get_success_button_style() -> str:
        """Get success/positive action button style (green)."""
        dark = Theme.is_dark_mode()
        color = "#28a745" if not dark else "#2ea44f"
        return Theme.get_button_style(color, dark)
    
    @staticmethod
    def get_destructive_button_style() -> str:
        """Get destructive action button style (red)."""
        dark = Theme.is_dark_mode()
        color = "#dc3545" if not dark else "#f85149"
        return Theme.get_button_style(color, dark)
    
    @staticmethod
    def get_destructive_text_style() -> str:
        """Get text color for destructive actions."""
        return "color: #dc3545; font-weight: bold;" if not Theme.is_dark_mode() else "color: #f85149; font-weight: bold;"
