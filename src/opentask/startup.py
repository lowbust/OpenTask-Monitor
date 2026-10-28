"""Conservative Run-key management with persistent, write-before-delete backups.

Only exact allowlisted Run/RunOnce locations can be changed. Startup-folder items are read-only.
No file is executed; scheduled tasks, drivers and services are not changed here.
"""
from __future__ import annotations

import hashlib
import json
import os
import tempfile
from dataclasses import asdict, dataclass
from pathlib import Path

from opentask.backend import OperationError, require_windows

RUN_KEY = r"Software\Microsoft\Windows\CurrentVersion\Run"
LOCATIONS = {"HKCU": ("HKCU", 64), "HKLM64": ("HKLM", 64), "HKLM32": ("HKLM", 32),
             "HKCU RunOnce": ("HKCU", 64), "HKLM64 RunOnce": ("HKLM", 64),
             "HKLM32 RunOnce": ("HKLM", 32)}
KEY_PATHS = {name: RUN_KEY + 'Once' if name.endswith('RunOnce') else RUN_KEY for name in LOCATIONS}


@dataclass(frozen=True)
class StartupEntry:
    id: str
    name: str
    command: str
    location: str
    value_type: int
    enabled: bool
    editable: bool = True


def entry_id(location: str, name: str) -> str:
    return hashlib.sha256(f"{location}\0{name.casefold()}".encode("utf-8")).hexdigest()


class WinRegistry:
    def __init__(self):
        require_windows()
        import winreg
        self.w = winreg

    def _key(self, location: str, *, write: bool = False):
        root, view = LOCATIONS[location]
        w = self.w
        access = (w.KEY_SET_VALUE | w.KEY_QUERY_VALUE) if write else w.KEY_READ
        access |= w.KEY_WOW64_64KEY if view == 64 else w.KEY_WOW64_32KEY
        return w.OpenKey(getattr(w, "HKEY_CURRENT_USER" if root == "HKCU" else "HKEY_LOCAL_MACHINE"),
                         KEY_PATHS[location], 0, access)

    def list(self, location: str) -> list[tuple[str, str, int]]:
        try:
            with self._key(location) as key:
                count = self.w.QueryInfoKey(key)[1]
                result = []
                for i in range(count):
                    name, data, kind = self.w.EnumValue(key, i)
                    if kind in (self.w.REG_SZ, self.w.REG_EXPAND_SZ) and isinstance(data, str):
                        result.append((name, data, kind))
                return result
        except FileNotFoundError:
            return []

    def get(self, location: str, name: str) -> tuple[str, int] | None:
        try:
            with self._key(location) as key:
                return self.w.QueryValueEx(key, name)
        except FileNotFoundError:
            return None

    def set(self, location: str, name: str, command: str, kind: int):
        with self._key(location, write=True) as key:
            self.w.SetValueEx(key, name, 0, kind, command)

    def delete(self, location: str, name: str):
        with self._key(location, write=True) as key:
            self.w.DeleteValue(key, name)


class BackupStore:
    def __init__(self, path: Path):
        self.path = path

    def load(self) -> dict[str, StartupEntry]:
        if not self.path.exists():
            return {}
        try:
            raw = json.loads(self.path.read_text(encoding="utf-8"))
            if raw.get("version") != 1 or not isinstance(raw.get("entries"), list):
                raise ValueError("Неподдерживаемый формат")
            result = {}
            for item in raw["entries"]:
                entry = StartupEntry(**item)
                if (entry.location not in LOCATIONS or entry.value_type not in (1, 2)
                        or not isinstance(entry.name, str) or not isinstance(entry.command, str)
                        or entry.id != entry_id(entry.location, entry.name)
                        or entry.enabled is not False or entry.editable is not True):
                    raise ValueError("Недопустимая запись")
                result[entry.id] = entry
            return result
        except (ValueError, TypeError, KeyError, AttributeError) as exc:
            raise OperationError(f"Повреждена резервная копия автозагрузки: {self.path}. "
                                 "Не удаляйте её; восстановите из своей копии.") from exc

    def save(self, entries: dict[str, StartupEntry]):
        self.path.parent.mkdir(parents=True, exist_ok=True)
        payload = {"version": 1, "entries": [asdict(e) for e in entries.values()]}
        fd, temporary = tempfile.mkstemp(prefix="startup-", suffix=".tmp", dir=self.path.parent)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as stream:
                json.dump(payload, stream, ensure_ascii=False, indent=2)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, self.path)
        finally:
            if os.path.exists(temporary):
                os.unlink(temporary)


class StartupManager:
    def __init__(self, registry, store: BackupStore):
        self.registry = registry
        self.store = store

    def entries(self) -> list[StartupEntry]:
        result = []
        for location in LOCATIONS:
            for name, command, kind in self.registry.list(location):
                result.append(StartupEntry(entry_id(location, name), name, command, location, kind, True))
        result.extend(self.store.load().values())
        return sorted(result, key=lambda e: (e.name.casefold(), e.location, not e.enabled))

    def toggle(self, entry: StartupEntry) -> str:
        if (not entry.editable or entry.location not in LOCATIONS or entry.value_type not in (1, 2)
                or entry.id != entry_id(entry.location, entry.name)):
            raise OperationError("Эту запись нельзя изменять.")
        backups = self.store.load()
        current = self.registry.get(entry.location, entry.name)
        if entry.enabled:
            if current != (entry.command, entry.value_type):
                raise OperationError("Запись уже изменилась. Обновите список.")
            if entry.id in backups:
                raise OperationError("Резервная копия уже существует. Сначала включите отключённую запись.")
            backups[entry.id] = StartupEntry(entry.id, entry.name, entry.command,
                                            entry.location, entry.value_type, False)
            self.store.save(backups)  # Must succeed before removing the live value.
            if self.registry.get(entry.location, entry.name) != current:
                raise OperationError("Запись изменилась во время операции. Копия сохранена, удаление отменено.")
            self.registry.delete(entry.location, entry.name)
            return "Запись отключена. Копия сохранена; уже запущенная программа не закрывалась."
        backup = backups.get(entry.id)
        if backup != entry:
            raise OperationError("Резервная копия изменилась. Обновите список.")
        if current is not None and current != (entry.command, entry.value_type):
            raise OperationError("На этом месте уже другая запись. Перезапись запрещена.")
        if current is None:
            self.registry.set(entry.location, entry.name, entry.command, entry.value_type)
        if self.registry.get(entry.location, entry.name) != (entry.command, entry.value_type):
            raise OperationError("Не удалось проверить восстановление. Резервная копия оставлена.")
        del backups[entry.id]
        self.store.save(backups)
        return "Запись восстановлена. Программа запустится при следующем входе в Windows."


def folder_entries() -> list[StartupEntry]:
    result = []
    roots = [
        Path(os.environ.get("APPDATA", "")) / r"Microsoft/Windows/Start Menu/Programs/Startup",
        Path(os.environ.get("PROGRAMDATA", r"C:\ProgramData")) / r"Microsoft/Windows/Start Menu/Programs/Startup",
    ]
    for root in roots:
        try:
            for path in root.iterdir():
                if path.is_file() and path.name.casefold() != "desktop.ini":
                    result.append(StartupEntry(str(path), path.name, str(path), "Папка Startup", 0, True, False))
        except (OSError, PermissionError):
            continue
    return result
