"""Background workers for long-running crypto operations.

The worker abstraction keeps CPU- and I/O-heavy tasks off the Qt GUI thread.
Cancellation is cooperative: it does not terminate the underlying crypto call,
but it prevents stale success/error signals from updating the UI after the user
has already moved on.
"""

from __future__ import annotations

from typing import Any, Callable

from PySide6.QtCore import QObject, QRunnable, Signal, Slot


class WorkerSignals(QObject):
    """Signals emitted by background workers."""

    finished = Signal()
    error = Signal(str)
    result = Signal(object)


class CryptoWorker(QRunnable):
    """Run a crypto operation in a thread pool thread.

    Usage::

        worker = CryptoWorker(hbz.encrypt_file, "in.txt", "out.hbzf", passphrase=b"pw")
        worker.signals.result.connect(on_done)
        worker.signals.error.connect(on_error)
        QThreadPool.globalInstance().start(worker)
    """

    def __init__(self, fn: Callable[..., Any], *args: Any, **kwargs: Any) -> None:
        super().__init__()
        self.fn = fn
        self.args = args
        self.kwargs = kwargs
        self.signals = WorkerSignals()
        self._cancelled = False

    def cancel(self) -> None:
        """Request that any late result/error notification be suppressed."""
        self._cancelled = True

    @Slot()
    def run(self) -> None:
        if self._cancelled:
            self.signals.finished.emit()
            return

        try:
            result = self.fn(*self.args, **self.kwargs)
            if not self._cancelled:
                self.signals.result.emit(result)
        except Exception as exc:
            if not self._cancelled:
                self.signals.error.emit(str(exc))
        finally:
            self.signals.finished.emit()
