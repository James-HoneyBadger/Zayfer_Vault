"""Drag-and-drop file input widget."""

from __future__ import annotations

from pathlib import Path

from PySide6.QtCore import Qt, Signal
from PySide6.QtGui import QDragEnterEvent, QDropEvent
from PySide6.QtWidgets import QLineEdit

_DEFAULT_STYLE = """
    DragDropFileInput {
        padding: 8px;
        border: 2px dashed palette(mid);
        border-radius: 4px;
    }
    DragDropFileInput:hover {
        border-color: #0078d7;
    }
    DragDropFileInput:focus {
        border-style: solid;
        border-color: #0078d7;
    }
"""

_DRAG_ACTIVE_STYLE = """
    DragDropFileInput {
        padding: 8px;
        border: 2px solid #0078d7;
        border-radius: 4px;
        background-color: palette(highlight);
    }
"""


class DragDropFileInput(QLineEdit):
    """Line edit that accepts file drops."""

    fileDropped = Signal(str)  # Emitted when a file is dropped

    def __init__(self, parent=None, placeholder: str = "Drag file here or click Browse...") -> None:
        super().__init__(parent)
        self.setAcceptDrops(True)
        self.setPlaceholderText(placeholder)
        self.setStyleSheet(_DEFAULT_STYLE)

    def dragEnterEvent(self, event: QDragEnterEvent) -> None:
        """Accept drag events with file URLs."""
        if event.mimeData().hasUrls():
            for url in event.mimeData().urls():
                if url.isLocalFile():
                    path = Path(url.toLocalFile())
                    if path.is_file():
                        event.acceptProposedAction()
                        self.setStyleSheet(_DRAG_ACTIVE_STYLE)
                        return
        event.ignore()

    def dragLeaveEvent(self, event) -> None:
        """Reset styling when drag leaves."""
        self.setStyleSheet(_DEFAULT_STYLE)

    def dropEvent(self, event: QDropEvent) -> None:
        """Handle file drop."""
        if event.mimeData().hasUrls():
            for url in event.mimeData().urls():
                if url.isLocalFile():
                    path = Path(url.toLocalFile())
                    if path.is_file():
                        file_path = str(path)
                        self.setText(file_path)
                        self.fileDropped.emit(file_path)
                        event.acceptProposedAction()
                        self.setStyleSheet(_DEFAULT_STYLE)
                        return
        event.ignore()
