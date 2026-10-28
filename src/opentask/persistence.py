"""Extended persistence inventory. Tasks and services are deliberately read-only."""
from __future__ import annotations

import base64
import json
import os
import subprocess
from pathlib import Path

from opentask.backend import list_services, require_windows


def scheduled_tasks() -> list[dict]:
    require_windows()
    # JSON is locale-independent, unlike schtasks /query CSV headings.
    script = '''$ErrorActionPreference='Stop'; [Console]::OutputEncoding=[Text.Encoding]::UTF8;
    $r=@(Get-ScheduledTask | ForEach-Object { [pscustomobject]@{
    Path=$_.TaskPath; Name=$_.TaskName; State=[string]$_.State;
    Hidden=$_.Settings.Hidden;
    Actions=(@($_.Actions | ForEach-Object { $_.Execute + ' ' + $_.Arguments }) -join '; ')
    }}); ConvertTo-Json -InputObject $r -Compress -Depth 4'''
    shell = Path(os.environ.get('SystemRoot', r'C:\Windows')) / 'System32/WindowsPowerShell/v1.0/powershell.exe'
    result = subprocess.run([str(shell), '-NoProfile', '-NonInteractive', '-EncodedCommand',
                             base64.b64encode(script.encode('utf-16-le')).decode('ascii')],
                            capture_output=True, timeout=35, creationflags=subprocess.CREATE_NO_WINDOW)
    if result.returncode:
        raise RuntimeError(result.stderr.decode('utf-8', 'replace')[-1200:])
    rows = json.loads(result.stdout.decode('utf-8-sig')) or []
    if isinstance(rows, dict):
        rows = [rows]
    return [{'Источник': 'Task Scheduler', 'Имя': row['Path'] + row['Name'],
             'Состояние': row['State'], 'Скрыто': str(row['Hidden']), 'Команда': row['Actions']}
            for row in rows]


def service_persistence() -> list[dict]:
    return [{'Источник': 'Service', 'Имя': row['name'], 'Состояние': row['status'],
             'Скрыто': '—', 'Команда': row['binpath'], 'Тип запуска': row['start_type']}
            for row in list_services() if row.get('start_type') in ('automatic', 'manual')]


def startup_folders() -> str:
    from opentask.startup import folder_entries
    return '\n'.join(row.command for row in folder_entries()) or 'Папки Startup пусты или недоступны.'

