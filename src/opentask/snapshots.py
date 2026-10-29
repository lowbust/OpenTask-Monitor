"""JSON snapshots and set comparison. No executable pickle, no clean/malicious label."""
from __future__ import annotations

import json
import ntpath
import os
import tempfile
import time
from dataclasses import asdict
from pathlib import Path

import psutil

from opentask import __version__
from opentask.backend import list_services
from opentask.startup import BackupStore, StartupManager, WinRegistry, folder_entries


def atomic_json(path: Path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix='opentask-', suffix='.tmp', dir=path.parent)
    try:
        with os.fdopen(fd, 'w', encoding='utf-8') as stream:
            json.dump(value, stream, ensure_ascii=False, indent=2)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def process_key(row) -> str:
    def value(name):
        return row.get(name, '') if isinstance(row, dict) else getattr(row, name, '')
    return '\0'.join([ntpath.normcase(ntpath.normpath(value('exe'))) if value('exe') else '',
                      value('name').casefold(), value('username').casefold()])


def capture(rows, data_dir: Path, include_tasks=False):
    snapshot = {'schema': 1, 'version': __version__, 'time': time.time(), 'boot': psutil.boot_time(),
                'processes': [asdict(row) for row in rows], 'services': [], 'startup': [], 'tasks': [], 'errors': [],
                'coverage': {'processes': True, 'services': True, 'startup': True, 'tasks': bool(include_tasks)}}
    try:
        snapshot['services'] = list_services()
    except Exception as exc:
        snapshot['coverage']['services'] = False
        snapshot['errors'].append('Службы: ' + str(exc))
    try:
        manager = StartupManager(WinRegistry(), BackupStore(data_dir / 'startup-backup.json'))
        snapshot['startup'] = [asdict(entry) for entry in manager.entries() + folder_entries()]
    except Exception as exc:
        snapshot['coverage']['startup'] = False
        snapshot['errors'].append('Автозагрузка: ' + str(exc))
    if include_tasks:
        try:
            from opentask.persistence import scheduled_tasks
            snapshot['tasks'] = scheduled_tasks()
        except Exception as exc:
            snapshot['coverage']['tasks'] = False
            snapshot['errors'].append('Задачи: ' + str(exc))
    return snapshot


def load(path: Path):
    if path.stat().st_size > 20_000_000:
        raise ValueError('Снимок превышает 20 МБ.')
    value = json.loads(path.read_text(encoding='utf-8-sig'))
    if not isinstance(value, dict) or value.get('schema') != 1:
        raise ValueError('Неизвестная схема снимка.')
    for group in ('processes', 'services', 'startup', 'tasks'):
        rows = value.get(group, [])
        if not isinstance(rows, list) or len(rows) > 30000 or any(not isinstance(row, dict) for row in rows):
            raise ValueError('Повреждён список ' + group)
    if not isinstance(value.get('coverage', {}), dict):
        raise ValueError('Неверное описание покрытия.')
    if any(not all(isinstance(row.get(name, ''), str) for name in ('name', 'exe', 'username'))
           for row in value.get('processes', [])):
        raise ValueError('Неверные поля процессов в снимке.')
    for group, names in [('services', ('name',)), ('startup', ('name', 'location', 'command')), ('tasks', ('Имя',))]:
        if any(not all(isinstance(row.get(name, ''), str) for name in names) for row in value.get(group, [])):
            raise ValueError('Неверные поля ' + group)
    return value


def compare(baseline: dict, current: dict):
    result = []
    def identity(group, row):
        if group == 'processes':
            return process_key(row)
        if group == 'startup':
            return row.get('location', '') + '\0' + row.get('name', '').casefold()
        if group == 'tasks':
            return row.get('Имя', '')
        return row.get('name', '')
    def stable(group, row):
        if group == 'processes':
            return {key: row.get(key) for key in ('name', 'exe', 'username')}
        if group == 'services':
            return {key: row.get(key) for key in ('name', 'binpath', 'start_type', 'username')}
        if group == 'startup':
            return {key: row.get(key) for key in ('name', 'location', 'command', 'enabled')}
        return row
    for group in ('processes', 'services', 'startup', 'tasks'):
        if baseline.get('coverage', {}).get(group) is False or current.get('coverage', {}).get(group) is False:
            result.append({'Раздел': group, 'Изменение': 'Не сравнивалось', 'Элемент': 'Недостаточно данных',
                           'Данные': 'Раздел не собирался или доступен не полностью; нет вывода об отсутствии элементов.'})
            continue
        old = {identity(group, row): row for row in baseline.get(group, [])}
        new = {identity(group, row): row for row in current.get(group, [])}
        for key in sorted(old.keys() | new.keys()):
            if key not in old:
                change, row = 'Добавлено', new[key]
            elif key not in new:
                change, row = 'Удалено', old[key]
            elif stable(group, old[key]) != stable(group, new[key]):
                change, row = 'Изменено', new[key]
            else:
                continue
            result.append({'Раздел': group, 'Изменение': change,
                           'Элемент': row.get('name') or row.get('Имя') or key.replace('\0', ' | '),
                           'Данные': json.dumps(stable(group, row), ensure_ascii=False)})
    return result
