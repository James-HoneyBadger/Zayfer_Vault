"""Toast notification system for user feedback."""

from __future__ import annotations

from PySide6.QtWidgets import QWidget, QLabel, QVBoxLayout, QGraphicsOpacityEffect
from PySide6.QtCore import Qt, QTimer, QPropertyAnimation, QEasingCurve, Property
from PySide6.QtGui import QPalette


class ToastNotification(QWidget):
    """A toast notification widget that appears temporarily."""
    
    def __init__(self, message: str, toast_type: str = "info", parent: QWidget | None = None):
        super().__init__(parent)
        self.setWindowFlags(Qt.WindowType.FramelessWindowHint | Qt.WindowType.Tool | Qt.WindowType.WindowStaysOnTopHint)
        self.setAttribute(Qt.WidgetAttribute.WA_TranslucentBackground)
        self.setAttribute(Qt.WidgetAttribute.WA_ShowWithoutActivating)
        
        # Setup UI
        layout = QVBoxLayout(self)
        layout.setContentsMargins(16, 12, 16, 12)
        
        self.label = QLabel(message)
        self.label.setWordWrap(True)
        self.label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        
        # Style based on type
        if toast_type == "success":
            bg_color = "#28a745" if self._is_dark_mode() else "#d4edda"
            text_color = "#ffffff" if self._is_dark_mode() else "#155724"
            border_color = "#1e7e34" if self._is_dark_mode() else "#c3e6cb"
            icon = "✓"
        elif toast_type == "error":
            bg_color = "#dc3545" if self._is_dark_mode() else "#f8d7da"
            text_color = "#ffffff" if self._is_dark_mode() else "#721c24"
            border_color = "#bd2130" if self._is_dark_mode() else "#f5c6cb"
            icon = "✗"
        elif toast_type == "warning":
            bg_color = "#ffc107" if self._is_dark_mode() else "#fff3cd"
            text_color = "#000000" if self._is_dark_mode() else "#856404"
            border_color = "#e0a800" if self._is_dark_mode() else "#ffeaa7"
            icon = "⚠"
        else:  # info
            bg_color = "#17a2b8" if self._is_dark_mode() else "#d1ecf1"
            text_color = "#ffffff" if self._is_dark_mode() else "#0c5460"
            border_color = "#117a8b" if self._is_dark_mode() else "#bee5eb"
            icon = "ℹ"
        
        self.label.setText(f"{icon}  {message}")
        self.label.setStyleSheet(f"""
            QLabel {{
                background-color: {bg_color};
                color: {text_color};
                border: 2px solid {border_color};
                border-radius: 6px;
                padding: 12px 20px;
                font-size: 13px;
                font-weight: 500;
            }}
        """)
        
        layout.addWidget(self.label)
        
        # Setup opacity effect
        self.opacity_effect = QGraphicsOpacityEffect(self)
        self.setGraphicsEffect(self.opacity_effect)
        
        # Animation for fade in/out
        self.fade_animation = QPropertyAnimation(self.opacity_effect, b"opacity")
        self.fade_animation.setEasingCurve(QEasingCurve.Type.InOutQuad)
        
    def _is_dark_mode(self) -> bool:
        """Check if dark mode is active."""
        from .theme import Theme
        return Theme.is_dark_mode()
    
    def show_notification(self, duration: int = 3000) -> None:
        """Show the notification with fade in/out.
        
        Args:
            duration: Display duration in milliseconds
        """
        # Position at bottom-right of parent using global coordinates
        if self.parent():
            parent_widget = self.parent()
            self.adjustSize()
            # Map parent's bottom-right to global coordinates for correct placement
            parent_global = parent_widget.mapToGlobal(parent_widget.rect().bottomRight())
            x = parent_global.x() - self.width() - 20
            y = parent_global.y() - self.height() - 60  # Account for status bar
            self.move(x, y)
        
        # Fade in
        self.opacity_effect.setOpacity(0.0)
        self.show()
        
        self.fade_animation.stop()
        self.fade_animation.setDuration(300)
        self.fade_animation.setStartValue(0.0)
        self.fade_animation.setEndValue(1.0)
        self.fade_animation.start()
        
        # Auto-hide after duration
        QTimer.singleShot(duration, self._fade_out)
    
    def _fade_out(self) -> None:
        """Fade out and close the notification."""
        self.fade_animation.stop()
        self.fade_animation.setDuration(300)
        self.fade_animation.setStartValue(1.0)
        self.fade_animation.setEndValue(0.0)
        self.fade_animation.finished.connect(self.close)
        self.fade_animation.start()


class NotificationManager:
    """Manages toast notifications for the application."""
    
    def __init__(self, parent: QWidget):
        self.parent = parent
        self.active_notifications: list[ToastNotification] = []
    
    def show_info(self, message: str, duration: int = 3000) -> None:
        """Show an info notification."""
        self._show_toast(message, "info", duration)
    
    def show_success(self, message: str, duration: int = 3000) -> None:
        """Show a success notification."""
        self._show_toast(message, "success", duration)
    
    def show_error(self, message: str, duration: int = 4000) -> None:
        """Show an error notification."""
        self._show_toast(message, "error", duration)
    
    def show_warning(self, message: str, duration: int = 3500) -> None:
        """Show a warning notification."""
        self._show_toast(message, "warning", duration)
    
    def _show_toast(self, message: str, toast_type: str, duration: int) -> None:
        """Create and show a toast notification."""
        # Clean up finished notifications
        self.active_notifications = [n for n in self.active_notifications if n.isVisible()]
        
        # Create new notification
        toast = ToastNotification(message, toast_type, self.parent)
        
        # Compute stacking offset before showing to avoid flicker
        offset = len(self.active_notifications)
        self.active_notifications.append(toast)
        
        toast.show_notification(duration)
        
        # Adjust Y position for stacking (move upward for each active toast)
        if offset > 0:
            current_y = toast.y()
            toast.move(toast.x(), current_y - (offset * (toast.height() + 10)))
