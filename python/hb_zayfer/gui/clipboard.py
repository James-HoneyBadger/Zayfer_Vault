"""Clipboard utilities with auto-clear for sensitive data.

Usage::

    from hb_zayfer.gui.clipboard import secure_copy

    # Copy text and auto-clear after the configured timeout
    secure_copy("sensitive passphrase", parent_widget)
"""

from __future__ import annotations

from PySide6.QtCore import QTimer
from PySide6.QtWidgets import QApplication

# ---------------------------------------------------------------------------
# Module-level timer shared by all callers so each new copy resets the clock.
# ---------------------------------------------------------------------------
_clear_timer: QTimer | None = None
_copied_text: str | None = None

# Default timeout in seconds (0 = disabled)
_auto_clear_seconds: int = 30


def set_auto_clear_timeout(seconds: int) -> None:
    """Set the clipboard auto-clear timeout (0 to disable)."""
    global _auto_clear_seconds
    _auto_clear_seconds = max(0, seconds)


def get_auto_clear_timeout() -> int:
    """Return the current auto-clear timeout in seconds."""
    return _auto_clear_seconds


def _ensure_timer() -> QTimer:
    """Create (or return) the module-level single-shot timer."""
    global _clear_timer
    if _clear_timer is None:
        _clear_timer = QTimer()
        _clear_timer.setSingleShot(True)
        _clear_timer.timeout.connect(_on_clear)
    return _clear_timer


def _on_clear() -> None:
    """Clear the clipboard if it still contains the text we placed there."""
    global _copied_text
    app = QApplication.instance()
    if app is None:
        _copied_text = None
        return
    clipboard = app.clipboard()
    if clipboard is not None and _copied_text is not None:
        # Only clear if the clipboard still holds our text (user may have
        # copied something else in the meantime).
        if clipboard.text() == _copied_text:
            clipboard.clear()
    _copied_text = None


def secure_copy(text: str, *, sensitive: bool = True) -> None:
    """Copy *text* to the system clipboard.

    When *sensitive* is ``True`` **and** the auto-clear timeout is > 0, a
    timer is started that will blank the clipboard after the configured
    number of seconds.

    Parameters
    ----------
    text:
        The string to place on the clipboard.
    sensitive:
        Whether this data should be auto-cleared.  Set ``False`` for
        non-secret items (e.g. contact names).
    """
    global _copied_text
    app = QApplication.instance()
    if app is None:
        return
    clipboard = app.clipboard()
    if clipboard is None:
        return

    clipboard.setText(text)

    if sensitive and _auto_clear_seconds > 0:
        _copied_text = text
        timer = _ensure_timer()
        # (Re-)start so new copies reset the countdown
        timer.start(_auto_clear_seconds * 1000)
    else:
        # Stop any pending clear for a non-sensitive copy
        if _clear_timer is not None and _clear_timer.isActive():
            _clear_timer.stop()
        _copied_text = None
