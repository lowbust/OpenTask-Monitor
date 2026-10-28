"""Portable runtime entry point, launched by the native EXE. No installation."""
from __future__ import annotations

import ctypes
import os
import sys
import traceback
from pathlib import Path


def run() -> int:
    try:
        from opentask.__main__ import main
        return main()
    except Exception:
        details = traceback.format_exc()
        folder = Path(os.environ.get('LOCALAPPDATA', str(Path.home()))) / 'OpenTaskMonitor'
        try:
            folder.mkdir(parents=True, exist_ok=True)
            (folder / 'startup-error.log').write_text(details, encoding='utf-8')
            location = str(folder / 'startup-error.log')
        except OSError:
            location = details[-1200:]
        ctypes.windll.user32.MessageBoxW(None,
            ('Не удалось загрузить встроенные компоненты OpenTask Monitor.\n\n'
             if os.environ.get('OPENTASK_SINGLEFILE') else
             'Не удалось запустить OpenTask Monitor.\nРаспакуйте весь архив в обычную папку.\n\n')
            + 'Диагностика:\n' + location, 'OpenTask Monitor', 0x10)
        return 1


if __name__ == '__main__':
    sys.exit(run())
