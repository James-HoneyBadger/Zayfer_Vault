"""Background workers for long-running crypto operations."""

from __future__ import annotations

from typing import Any, Callable, Optional

from PySide6.QtCore import QObject, QRunnable, Signal, Slot


class WorkerSignals(QObject):
    """Signals emitted by background workers."""

    finished = Signal()
    error = Signal(str)
    result = Signal(object)
    progress = Signal(int)  # 0-100


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

    @Slot()
    def run(self) -> None:
        try:
            result = self.fn(*self.args, **self.kwargs)
            self.signals.result.emit(result)
        except Exception as exc:
            self.signals.error.emit(str(exc))
        finally:
            self.signals.finished.emit()
