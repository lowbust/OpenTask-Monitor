"""Pure helpers shared by the UI, collectors and tests."""
from __future__ import annotations

import csv
import io
from dataclasses import dataclass
from datetime import datetime
from typing import Any


@dataclass(frozen=True)
class ProcessRow:
    pid: int
    ppid: int
    name: str
    username: str
    cpu: float
    memory: int
    threads: int
    status: str
    created: float
    exe: str = ""
    findings: str = ""
    triage: int = 0
    score_notes: str = ""


@dataclass(frozen=True)
class Snapshot:
    processes: tuple[ProcessRow, ...]
    cpu: float
    memory_percent: float
    memory_used: int
    memory_total: int
    net_recv: float
    net_sent: float
    disk_read: float
    disk_write: float
    sampled_at: float
    errors: int = 0
    collection_ms: float = 0.0


def human_bytes(value: float) -> str:
    value = max(0.0, float(value))
    for unit in ("Б", "КиБ", "МиБ", "ГиБ", "ТиБ"):
        if value < 1024 or unit == "ТиБ":
            return f"{value:.1f} {unit}"
        value /= 1024
    return "0 Б"


def counter_rate(current: int, previous: int, elapsed: float) -> float:
    """Never return a negative rate after counter reset or adapter replacement."""
    return max(0, current - previous) / elapsed if elapsed > 0 else 0.0


def identity_matches(expected: float, actual: float) -> bool:
    return abs(expected - actual) < 0.001


def spreadsheet_safe(value: Any) -> str:
    text = str(value)
    # CSV can be opened by spreadsheet applications. Do not execute process names as formulas.
    if text.lstrip().startswith(("=", "+", "-", "@")) or text.startswith(("\t", "\r", "\n")):
        return "'" + text
    return text


def processes_csv(rows: list[ProcessRow]) -> str:
    output = io.StringIO(newline="")
    writer = csv.writer(output)
    writer.writerow(["PID", "PPID", "Name", "User", "CPU %", "RSS bytes", "Threads", "Status", "Started", "Path", "Priority", "Priority reasons"])
    for p in rows:
        writer.writerow([
            p.pid, p.ppid, spreadsheet_safe(p.name), spreadsheet_safe(p.username),
            round(p.cpu, 2), p.memory, p.threads, spreadsheet_safe(p.status),
            datetime.fromtimestamp(p.created).isoformat(timespec="seconds") if p.created else "",
            spreadsheet_safe(p.exe), p.triage, spreadsheet_safe(p.score_notes),
        ])
    return output.getvalue()
