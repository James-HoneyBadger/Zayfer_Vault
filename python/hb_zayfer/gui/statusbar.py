"""Status bar component for the main window."""

from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtWidgets import QLabel, QStatusBar


class StatusBar(QStatusBar):
    """Enhanced status bar with multiple sections."""

    def __init__(self) -> None:
        super().__init__()

        # Main message label (left side)
        self.message_label = QLabel("Ready")
        self.addWidget(self.message_label, 1)

        # Operation status (center-right)
        self.operation_label = QLabel("")
        self.operation_label.setAlignment(Qt.AlignmentFlag.AlignRight)
        self.addPermanentWidget(self.operation_label)

        # Item count (right)
        self.count_label = QLabel("")
        self.count_label.setAlignment(Qt.AlignmentFlag.AlignRight)
        self.addPermanentWidget(self.count_label)

    def set_message(self, message: str, timeout: int = 0) -> None:
        """Set the main status message.
        
        Args:
            message: The message to display
            timeout: Display timeout in milliseconds (0 for permanent)
        """
        if timeout > 0:
            self.showMessage(message, timeout)
        else:
            self.message_label.setText(message)

    def set_operation(self, operation: str) -> None:
        """Set the current operation status.
        
        Args:
            operation: Description of current operation
        """
        self.operation_label.setText(operation)

    def clear_operation(self) -> None:
        """Clear the operation status."""
        self.operation_label.setText("")

    def set_count(self, label: str, count: int) -> None:
        """Set the item count display.
        
        Args:
            label: Label for the count (e.g., "Keys", "Contacts")
            count: Number of items
        """
        self.count_label.setText(f"{label}: {count}")

    def clear_count(self) -> None:
        """Clear the count display."""
        self.count_label.setText("")
