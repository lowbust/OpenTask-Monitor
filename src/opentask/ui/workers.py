from __future__ import annotations

import threading
import traceback
from collections.abc import Callable

from PySide6.QtCore import QObject, QRunnable, QThread, Signal

from opentask.backend import Collector


class MonitorThread(QThread):
    snapshot = Signal(object)
    error = Signal(str)

    def __init__(self, parent=None):
        super().__init__(parent)
        self.stop_event = threading.Event()
        self.paused = threading.Event()
        self.interval = 1.5

    def run(self):
        collector = Collector()
        while not self.stop_event.is_set():
            if not self.paused.is_set():
                try:
                    self.snapshot.emit(collector.collect())
                except Exception as exc:
                    self.error.emit(f"Ошибка мониторинга: {exc}")
            self.stop_event.wait(self.interval)

    def stop(self):
        self.stop_event.set()


class TaskSignals(QObject):
    result = Signal(object)
    error = Signal(str)
    finished = Signal()


class Task(QRunnable):
    def __init__(self, fn: Callable):
        super().__init__()
        self.fn = fn
        self.signals = TaskSignals()

    def run(self):
        try:
            self.signals.result.emit(self.fn())
        except Exception as exc:
            import logging
            logging.getLogger(__name__).debug("Background task failed\n%s", traceback.format_exc())
            self.signals.error.emit(f"{type(exc).__name__}: {exc}")
        finally:
            self.signals.finished.emit()


class SignatureThread(QThread):
    result = Signal(str, object)

    def __init__(self, parent=None):
        super().__init__(parent)
        from collections import deque
        self.queue = deque()
        self.queued = set()
        self.guard = threading.Lock()
        self.stopping = threading.Event()
        self.enabled = False

    def enqueue(self, paths):
        with self.guard:
            for path in paths:
                if path and not path.startswith('\\\\') and path not in self.queued and len(self.queue) < 4096:
                    self.queue.append(path)
                    self.queued.add(path)

    def run(self):
        from opentask.signatures import Signature, verify_signature
        while not self.stopping.is_set():
            path = None
            with self.guard:
                if self.enabled and self.queue:
                    path = self.queue.popleft()
            if path:
                try:
                    self.result.emit(path, verify_signature(path))
                except Exception:
                    self.result.emit(path, Signature('проверка недоступна'))
                finally:
                    with self.guard:
                        self.queued.discard(path)
            self.stopping.wait(0.1)

    def stop(self):
        self.stopping.set()
