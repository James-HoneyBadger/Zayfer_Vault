"""Shared base helpers for GUI views.

This module provides :class:`ViewBase`, a thin mixin used (incrementally) by
the various ``*_view.py`` widgets to eliminate the most common duplicated
patterns observed across the GUI:

* ``_notify(...)`` — toast notification with safe fallback to :class:`QMessageBox`
* ``_browse_open_file(...)`` / ``_browse_save_file(...)`` — file dialog wrappers
  remembering the last directory through :class:`SettingsManager`
* ``_run_worker(...)`` — submit a :class:`CryptoWorker`-style callable to the
  thread pool with consistent progress / error handling

The mixin is intentionally optional — existing views continue to work
unchanged. New views and refactor passes can opt in by inheriting from
``ViewBase`` *before* :class:`QWidget`.
"""

from __future__ import annotations

from pathlib import Path
from typing import Callable

from PySide6.QtCore import QThreadPool
from PySide6.QtWidgets import QFileDialog, QMessageBox, QWidget


class ViewBase:
    """Mixin providing shared notification and file-dialog helpers.

    Inherit alongside :class:`QWidget` (mixin first so MRO is well-defined)::

        class MyView(ViewBase, QWidget):
            ...
    """

    # ----------------------------- notifications ----------------------------

    def _notify(
        self,
        message: str,
        level: str = "info",
        *,
        title: str | None = None,
    ) -> None:
        """Show a toast notification, falling back to a modal dialog.

        ``level`` is one of ``"info"``, ``"success"``, ``"warning"``, ``"error"``.
        """
        manager = self._notification_manager()
        if manager is not None:
            method = {
                "info": manager.show_info,
                "success": manager.show_success,
                "warning": manager.show_warning,
                "error": manager.show_error,
            }.get(level, manager.show_info)
            method(message)
            return

        # Fallback — no notification manager attached to the main window.
        widget = self if isinstance(self, QWidget) else None
        box = {
            "error": QMessageBox.critical,
            "warning": QMessageBox.warning,
        }.get(level, QMessageBox.information)
        box(widget, title or level.title(), message)

    def _notification_manager(self):
        """Walk the parent chain looking for a ``notifications`` attribute."""
        widget = self if isinstance(self, QWidget) else None
        while widget is not None:
            mgr = getattr(widget, "notifications", None)
            if mgr is not None:
                return mgr
            widget = widget.parent()
        return None

    # ----------------------------- file dialogs -----------------------------

    def _browse_open_file(
        self,
        caption: str = "Open file",
        *,
        filters: str = "All files (*.*)",
        remember_key: str | None = None,
    ) -> Path | None:
        """Open-file dialog. Returns the selected path or ``None``."""
        start = self._last_dir(remember_key)
        widget = self if isinstance(self, QWidget) else None
        path, _ = QFileDialog.getOpenFileName(widget, caption, start, filters)
        if not path:
            return None
        result = Path(path)
        self._remember_dir(remember_key, result.parent)
        return result

    def _browse_save_file(
        self,
        caption: str = "Save file",
        *,
        filters: str = "All files (*.*)",
        suggested_name: str = "",
        remember_key: str | None = None,
    ) -> Path | None:
        """Save-file dialog. Returns the selected path or ``None``."""
        start = self._last_dir(remember_key)
        if suggested_name:
            start = str(Path(start) / suggested_name)
        widget = self if isinstance(self, QWidget) else None
        path, _ = QFileDialog.getSaveFileName(widget, caption, start, filters)
        if not path:
            return None
        result = Path(path)
        self._remember_dir(remember_key, result.parent)
        return result

    def _last_dir(self, key: str | None) -> str:
        if not key:
            return str(Path.home())
        settings = self._settings_manager()
        if settings is not None:
            value = settings.get(f"last_paths.{key}", "")
            if value:
                return value
        return str(Path.home())

    def _remember_dir(self, key: str | None, directory: Path) -> None:
        if not key:
            return
        settings = self._settings_manager()
        if settings is None:
            return
        settings.set(f"last_paths.{key}", str(directory))
        settings.save()

    def _settings_manager(self):
        widget = self if isinstance(self, QWidget) else None
        while widget is not None:
            mgr = getattr(widget, "settings", None)
            if mgr is not None and hasattr(mgr, "get") and hasattr(mgr, "set"):
                return mgr
            widget = widget.parent()
        return None

    # ----------------------------- worker helper ----------------------------

    def _run_worker(
        self,
        worker,
        *,
        on_finished: Callable | None = None,
        on_error: Callable | None = None,
        on_progress: Callable | None = None,
    ):
        """Wire common signals on a :class:`CryptoWorker`-like object and
        submit it to the global :class:`QThreadPool`.

        The worker is expected to expose ``signals`` with ``finished``,
        ``error`` and (optionally) ``progress``.
        """
        signals = getattr(worker, "signals", None)
        if signals is not None:
            if on_finished is not None and hasattr(signals, "finished"):
                signals.finished.connect(on_finished)
            if on_error is not None and hasattr(signals, "error"):
                signals.error.connect(on_error)
            if on_progress is not None and hasattr(signals, "progress"):
                signals.progress.connect(on_progress)
        QThreadPool.globalInstance().start(worker)
        return worker
