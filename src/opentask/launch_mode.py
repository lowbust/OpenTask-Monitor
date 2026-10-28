"""Shared launch preference for the native launcher and Qt UI.

Plain ASCII INI intentionally matches GetPrivateProfileIntW. No API keys or
sensitive values are stored. The change applies to the next native EXE launch.
"""
from __future__ import annotations

import configparser
import os
import tempfile
from pathlib import Path


def random_enabled(data_dir: Path) -> bool:
    parser = configparser.ConfigParser(interpolation=None)
    try:
        with (data_dir / 'launch.ini').open(encoding='ascii') as stream:
            parser.read_file(stream)
        return parser.get('Launch', 'RandomName', fallback='0').strip() == '1'
    except (OSError, UnicodeError, configparser.Error):
        return False


def set_random_enabled(data_dir: Path, enabled: bool) -> None:
    data_dir.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix='launch-', suffix='.tmp', dir=data_dir)
    try:
        with os.fdopen(fd, 'w', encoding='ascii', newline='') as stream:
            stream.write('[Launch]\r\nRandomName=' + ('1' if enabled else '0') + '\r\n')
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, data_dir / 'launch.ini')
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)
