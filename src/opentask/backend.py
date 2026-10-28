"""System access. No shell=True and no implicit privilege escalation."""
from __future__ import annotations

import os
import platform
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path

import psutil

from opentask.core import ProcessRow, Snapshot, counter_rate, human_bytes, identity_matches

CRITICAL_NAMES = frozenset({
    "system", "registry", "secure system", "idle", "system idle process", "smss.exe",
    "csrss.exe", "wininit.exe", "services.exe", "lsass.exe", "winlogon.exe",
    "fontdrvhost.exe", "memory compression",
})


class OperationError(RuntimeError):
    pass


def require_windows() -> None:
    if sys.platform != "win32":
        raise OperationError("Эта операция доступна только в Windows.")


def is_admin() -> bool:
    if sys.platform != "win32":
        return False
    import ctypes
    return bool(ctypes.windll.shell32.IsUserAnAdmin())


def checked_process(pid: int, created: float, *, mutation: bool = False) -> psutil.Process:
    if mutation and pid in (0, 4, os.getpid()):
        raise OperationError("Изменение этого процесса заблокировано для безопасности.")
    p = psutil.Process(pid)
    if not identity_matches(created, p.create_time()):
        raise OperationError("PID уже принадлежит другому процессу. Обновите список.")
    if mutation and p.name().casefold() in CRITICAL_NAMES:
        raise OperationError("Изменение критического системного процесса заблокировано.")
    return p


def process_action(pid: int, created: float, action: str) -> str:
    require_windows()
    p = checked_process(pid, created, mutation=True)
    priorities = {
        "idle": psutil.IDLE_PRIORITY_CLASS,
        "below": psutil.BELOW_NORMAL_PRIORITY_CLASS,
        "normal": psutil.NORMAL_PRIORITY_CLASS,
        "above": psutil.ABOVE_NORMAL_PRIORITY_CLASS,
        "high": psutil.HIGH_PRIORITY_CLASS,
    }
    if action == "terminate":
        p.terminate()
    elif action == "suspend":
        p.suspend()
    elif action == "resume":
        p.resume()
    elif action in priorities:
        p.nice(priorities[action])
    else:
        raise OperationError("Неизвестная операция.")
    return f"Операция «{action}» выполнена для PID {pid}."


def process_details(pid: int, created: float) -> dict[str, str]:
    p = checked_process(pid, created)
    details = {"PID": str(pid)}
    getters = {
        "Имя": p.name, "Родительский PID": p.ppid, "Путь": p.exe,
        "Командная строка": lambda: subprocess.list2cmdline(p.cmdline()),
        "Пользователь": p.username, "Рабочая папка": p.cwd,
        "Статус": p.status, "Потоки": p.num_threads,
        "Приоритет": lambda: str(p.nice()),
        "Запущен": lambda: datetime.fromtimestamp(p.create_time()).isoformat(sep=" ", timespec="seconds"),
        "Память RSS": lambda: human_bytes(p.memory_info().rss),
        "Потоки ввода/вывода": lambda: str(p.io_counters()),
        "Дескрипторы": p.num_handles if sys.platform == "win32" else p.num_fds,
    }
    for key, getter in getters.items():
        try:
            details[key] = str(getter())
        except (psutil.Error, OSError) as exc:
            details[key] = f"Недоступно ({type(exc).__name__})"
    return details


def show_process_file(pid: int, created: float) -> str:
    require_windows()
    executable = checked_process(pid, created).exe()
    if not executable or not Path(executable).is_file():
        raise OperationError("Путь к исполняемому файлу недоступен.")
    explorer = Path(os.environ.get("SystemRoot", r"C:\Windows")) / "explorer.exe"
    subprocess.Popen([str(explorer), "/select,", executable], shell=False)
    return "Файл показан в Проводнике."


class Collector:
    def __init__(self) -> None:
        self.previous_time: float | None = None
        self.previous_net = None
        self.previous_disk = None
        self.seen: set[tuple[int, float]] = set()
        self.metadata = {}
        psutil.cpu_percent(interval=None)

    def collect(self) -> Snapshot:
        started = time.perf_counter()
        now = time.monotonic()
        elapsed = now - self.previous_time if self.previous_time is not None else 0
        cpu_count = psutil.cpu_count() or 1
        rows = []
        errors = 0
        seen = set()
        active_pids = set()
        for p in psutil.process_iter():
            active_pids.add(p.pid)
            try:
                cached = self.metadata.get(p.pid)
                if cached is None or now - cached[0] >= 15:
                    def safe(getter, fallback):
                        try:
                            return getter()
                        except (psutil.Error, OSError):
                            return fallback
                    with p.oneshot():
                        created = p.create_time()
                        meta = (created, safe(p.ppid, 0), safe(p.name, "—"),
                                safe(p.username, "Недоступно"), safe(p.num_threads, 0),
                                safe(p.status, "unknown"), safe(p.exe, ""))
                    self.metadata[p.pid] = (now, meta)
                else:
                    meta = cached[1]
                created, ppid, name, username, threads, status, exe = meta
                identity = (p.pid, created)
                seen.add(identity)
                with p.oneshot():
                    cpu = p.cpu_percent(interval=None)
                    rss = p.memory_info().rss
                if identity not in self.seen:
                    cpu = 0.0
                rows.append(ProcessRow(p.pid, ppid, name, username,
                                       min(100.0, max(0.0, cpu / cpu_count)), rss,
                                       threads, status, created, exe))
            except (psutil.Error, OSError):
                errors += 1
        self.metadata = {pid: value for pid, value in self.metadata.items() if pid in active_pids}
        self.seen = seen
        memory = psutil.virtual_memory()
        net = psutil.net_io_counters()
        disk = psutil.disk_io_counters()

        def rate(current, previous, field):
            if current is None or previous is None:
                return 0.0
            return counter_rate(getattr(current, field), getattr(previous, field), elapsed)

        snapshot = Snapshot(
            tuple(rows), psutil.cpu_percent(interval=None), memory.percent,
            memory.used, memory.total,
            rate(net, self.previous_net, "bytes_recv"), rate(net, self.previous_net, "bytes_sent"),
            rate(disk, self.previous_disk, "read_bytes"), rate(disk, self.previous_disk, "write_bytes"),
            time.time(), errors, (time.perf_counter() - started) * 1000,
        )
        self.previous_time, self.previous_net, self.previous_disk = now, net, disk
        return snapshot


def list_services() -> list[dict]:
    require_windows()
    rows = []
    for service in psutil.win_service_iter():
        try:
            rows.append(service.as_dict())
        except (psutil.Error, OSError):
            continue
    return sorted(rows, key=lambda s: s["name"].casefold())


def service_action(name: str, action: str) -> str:
    require_windows()
    if action not in {"start", "stop"}:
        raise OperationError("Неизвестная операция службы.")
    # Resolve the exact service again; never accept an unverified arbitrary command.
    psutil.win_service_get(name).as_dict()
    sc = Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32" / "sc.exe"
    result = subprocess.run(
        [str(sc), action, name], capture_output=True, timeout=25, shell=False,
        creationflags=subprocess.CREATE_NO_WINDOW,
    )
    # sc.exe normally emits the active Windows OEM code page, not UTF-8.
    import ctypes
    encoding = f"cp{ctypes.windll.kernel32.GetOEMCP()}"
    output = (result.stdout + result.stderr).decode(encoding, errors="replace").strip()
    if result.returncode:
        raise OperationError(f"SC завершился с кодом {result.returncode}:\n{output}")
    return output or "Команда принята. Дождитесь изменения состояния службы."


def system_info() -> str:
    vm = psutil.virtual_memory()
    lines = [
        f"ОС: {platform.platform()}", f"Архитектура: {platform.machine()}",
        f"Процессор: {platform.processor() or 'Не определён'}",
        f"Ядра: {psutil.cpu_count(logical=False) or '—'} физических / {psutil.cpu_count()} логических",
        f"ОЗУ: {human_bytes(vm.total)}",
        f"Загрузка системы: {datetime.fromtimestamp(psutil.boot_time()):%Y-%m-%d %H:%M:%S}",
        f"Права администратора: {'да' if is_admin() else 'нет'}", "", "Диски:",
    ]
    for part in psutil.disk_partitions(all=False):
        try:
            usage = psutil.disk_usage(part.mountpoint)
            lines.append(f"  {part.device} ({part.fstype}) — {human_bytes(usage.used)} / "
                         f"{human_bytes(usage.total)} · {usage.percent}%")
        except (OSError, psutil.Error):
            lines.append(f"  {part.device} — недоступен")
    lines += ["", "Сетевые интерфейсы (состояние):"]
    for name, stat in psutil.net_if_stats().items():
        lines.append(f"  {name}: {'подключён' if stat.isup else 'отключён'} · {stat.speed} Мбит/с")
    return "\n".join(lines)
