from __future__ import annotations

import logging
import os
import sys
from logging.handlers import RotatingFileHandler
from pathlib import Path

from opentask import __version__


def data_directory() -> Path:
    return Path(os.environ.get("LOCALAPPDATA", str(Path.home() / "AppData" / "Local"))) / "OpenTaskMonitor"


def main() -> int:
    if "--handle-probe" in sys.argv:
        index = sys.argv.index("--handle-probe")
        sys.argv = [sys.argv[0], *sys.argv[index + 1:index + 3]]
        if sys.stdout is None:
            import ctypes
            import msvcrt
            from ctypes import wintypes
            api = ctypes.WinDLL('kernel32')
            api.GetStdHandle.argtypes = [wintypes.DWORD]
            api.GetStdHandle.restype = wintypes.HANDLE
            handle = api.GetStdHandle(0xfffffff5)
            sys.stdout = os.fdopen(msvcrt.open_osfhandle(handle, os.O_WRONLY), 'w', encoding='utf-8')
        from opentask.handle_probe import main as probe_main
        probe_main()
        return 0
    if "--version" in sys.argv:
        print(f"OpenTask Monitor {__version__}")
        return 0
    if sys.platform != "win32":
        print("OpenTask Monitor поддерживает Windows 10/11 x64. См. README.md.", file=sys.stderr)
        return 1

    from PySide6.QtCore import QLockFile, Qt, QTimer
    from PySide6.QtGui import QColor, QIcon, QPainter, QPen, QPixmap
    from PySide6.QtWidgets import QApplication, QMessageBox

    from opentask.ui.theme import STYLE
    from opentask.ui.window import MainWindow

    app = QApplication(sys.argv)
    app.setApplicationName("OpenTask Monitor")
    app.setOrganizationName("OpenTaskMonitor")
    app.setApplicationVersion(__version__)
    app.setStyle("Fusion")
    app.setStyleSheet(STYLE)
    try:
        data_dir = data_directory()
        data_dir.mkdir(parents=True, exist_ok=True)
        handler = RotatingFileHandler(data_dir / "opentask.log", maxBytes=1_000_000, backupCount=2,
                                      encoding="utf-8")
        handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s"))
        logging.basicConfig(level=logging.INFO, handlers=[handler])
    except OSError as exc:
        QMessageBox.critical(None, "OpenTask Monitor", f"Не удалось создать папку данных:\n{exc}")
        return 1
    lock = QLockFile(str(data_dir / "instance.lock"))
    # Do not mistake a long-running instance for a stale lock; dead PIDs are still detected.
    lock.setStaleLockTime(0)
    if not lock.tryLock(100):
        QMessageBox.information(None, "OpenTask Monitor", "Программа уже запущена либо папка данных недоступна.\n"
                                "Закройте другой экземпляр, прежде чем менять автозагрузку.")
        return 1

    def exception_hook(exc_type, exc, tb):
        logging.getLogger("opentask").critical("Unhandled exception", exc_info=(exc_type, exc, tb))
        QMessageBox.critical(None, "Ошибка приложения", f"{exc_type.__name__}: {exc}\n\n"
                              f"Диагностика: {data_dir / 'opentask.log'}")

    sys.excepthook = exception_hook
    # Unique taskbar identity; no registry writes or elevation.
    try:
        import ctypes
        ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID("OpenTaskMonitor.Desktop")
    except OSError:
        pass
    pixmap = QPixmap(64, 64)
    pixmap.fill(Qt.GlobalColor.transparent)
    painter = QPainter(pixmap)
    painter.setRenderHint(QPainter.RenderHint.Antialiasing)
    painter.setPen(Qt.PenStyle.NoPen)
    painter.setBrush(QColor("#1e344e"))
    painter.drawRoundedRect(1, 1, 62, 62, 14, 14)
    painter.setPen(QPen(QColor("#78bcff"), 5))
    for x, height in ((17, 18), (31, 36), (45, 27)):
        painter.drawLine(x, 49, x, 49 - height)
    painter.end()
    app.setWindowIcon(QIcon(pixmap))
    window = MainWindow(data_dir)
    if "--random-title" in sys.argv:
        import secrets
        window.setWindowTitle('OTM-' + secrets.token_hex(6))
    window.show()
    smoke_test = "--smoke-test" in sys.argv
    if smoke_test:
        QTimer.singleShot(3500, window.close)
    result = app.exec()
    lock.unlock()
    if smoke_test:
        snapshot = window.last_snapshot
        count = len(snapshot.processes) if snapshot else 0
        logging.getLogger("opentask").info(
            "Smoke test: %s processes; exit=%s; mode=%s; executable=%s", count, result,
            'random' if '--random-title' in sys.argv else 'normal', Path(sys.executable).name)
        if not count:
            return 2
    return result


if __name__ == "__main__":
    raise SystemExit(main())
