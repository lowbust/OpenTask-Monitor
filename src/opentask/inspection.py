"""On-demand inspection and explicitly confirmed destructive actions."""
from __future__ import annotations

import hashlib
import ipaddress
import json
import ntpath
import os
import re
import socket
import struct
import subprocess
import sys
import time
import urllib.error
import urllib.request
from functools import lru_cache
from pathlib import Path

import psutil

from opentask.backend import OperationError, checked_process, require_windows

SYSTEM_NAMES = {
    'svchost.exe', 'lsass.exe', 'services.exe', 'csrss.exe', 'wininit.exe',
    'winlogon.exe', 'smss.exe', 'taskhostw.exe', 'dwm.exe', 'conhost.exe',
    'dllhost.exe', 'spoolsv.exe', 'rundll32.exe',
}
SHELLS = {'cmd.exe', 'powershell.exe', 'pwsh.exe', 'wscript.exe', 'cscript.exe', 'mshta.exe'}


@lru_cache(maxsize=8192)
def path_findings(name: str, path: str, windows: str = r'C:\Windows') -> str:
    if not path:
        return ''
    normalized = ntpath.normcase(ntpath.normpath(path))
    root = ntpath.normcase(ntpath.normpath(windows))
    folders = [ntpath.join(root, 'system32'), ntpath.join(root, 'syswow64')]
    if name.casefold() == 'smss.exe':
        folders.append(ntpath.join(root, 'system32', 'smss'))
    if name.casefold() in SYSTEM_NAMES and ntpath.dirname(normalized) not in folders:
        return 'нетипичный путь системного имени'
    if name.casefold() == 'explorer.exe' and normalized != ntpath.join(root, 'explorer.exe'):
        return 'нетипичный путь explorer.exe'
    return ''


def parent_findings(row, parents: dict) -> str:
    parent = parents.get(row.ppid)
    # Parent PID can be reused after exit. Never imply a false relationship.
    if parent is None or parent.created > row.created:
        return ''
    if row.name.casefold() in SHELLS and parent.name.casefold() not in {
        'explorer.exe', 'cmd.exe', 'powershell.exe', 'pwsh.exe', 'windowsterminal.exe',
        'wt.exe', 'conhost.exe', 'opentaskmonitor.exe', 'python.exe', 'pythonw.exe',
    }:
        return f'проверьте родителя: {parent.name} ({parent.pid})'
    return ''


def hash_file(path: str) -> str:
    before = os.stat(path)
    digest = hashlib.sha256()
    with open(path, 'rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            digest.update(block)
    after = os.stat(path)
    if (before.st_size, before.st_mtime_ns) != (after.st_size, after.st_mtime_ns):
        raise OperationError('Файл изменился во время хеширования. Повторите проверку.')
    return digest.hexdigest()


def virustotal(path: str, key: str) -> dict:
    if not re.fullmatch(r'[0-9a-fA-F]{64}', key.strip()):
        raise OperationError('API-ключ VirusTotal должен содержать 64 hex-символа. Значение не записывается в лог.')
    digest = hash_file(path)
    request = urllib.request.Request('https://www.virustotal.com/api/v3/files/' + digest,
                                     headers={'x-apikey': key.strip(), 'Accept': 'application/json'})
    # Do not forward the API key through HTTP redirects.
    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, req, fp, code, msg, headers, newurl):
            return None
    try:
        with urllib.request.build_opener(NoRedirect()).open(request, timeout=20) as response:
            data = json.loads(response.read(2_000_000))['data']['attributes']
    except urllib.error.HTTPError as exc:
        explanations = {404: 'Хеш отсутствует в VirusTotal. Файл НЕ загружался.',
                        401: 'Неверный API-ключ VirusTotal.', 403: 'Нет доступа к VirusTotal API.',
                        429: 'Лимит VirusTotal исчерпан. Подождите или проверьте тариф.'}
        raise OperationError(explanations.get(exc.code, f'VirusTotal: HTTP {exc.code}')) from None
    return {'SHA-256': digest, 'Статистика': data.get('last_analysis_stats', {}),
            'Дата анализа Unix': data.get('last_analysis_date', 'нет'),
            'Ссылка': 'https://www.virustotal.com/gui/file/' + digest,
            'Важно': 'Это существующий отчёт по хешу, не новая проверка. 0 detections не гарантирует безопасность.'}


def dlls(pid: int, created: float) -> list[dict]:
    p = checked_process(pid, created)
    return [{'Путь': item.path, 'RSS': getattr(item, 'rss', 0)}
            for item in p.memory_maps(grouped=True) if item.path.lower().endswith('.dll')]


def connections(pid: int, created: float) -> list[dict]:
    p = checked_process(pid, created)
    rows = []
    for item in p.net_connections(kind='inet'):
        local = tuple(item.laddr) if item.laddr else ('', 0)
        remote = tuple(item.raddr) if item.raddr else ('', 0)
        rows.append({'Протокол': 'TCP' if item.type == socket.SOCK_STREAM else 'UDP',
                     'Семейство': 'IPv4' if item.family == socket.AF_INET else 'IPv6',
                     'Локальный IP': local[0], 'Порт': local[1], 'Удалённый IP': remote[0],
                     'Удалённый порт': remote[1], 'Состояние': item.status})
    return rows


def disconnect(pid: int, created: float, row: dict) -> str:
    require_windows()
    p = checked_process(pid, created, mutation=True)
    if row['Протокол'] != 'TCP' or row['Семейство'] != 'IPv4' or not row['Удалённый IP']:
        raise OperationError('Разрыв поддерживается только для установленного IPv4 TCP, не UDP/IPv6.')
    # Re-read ownership immediately before SetTcpEntry. The Windows API itself has no PID field.
    expected = (row['Локальный IP'], row['Порт'], row['Удалённый IP'], row['Удалённый порт'])
    current = connections(p.pid, created)
    if not any((r['Локальный IP'], r['Порт'], r['Удалённый IP'], r['Удалённый порт']) == expected
               and r['Протокол'] == 'TCP' for r in current):
        raise OperationError('Соединение уже исчезло. Обновите список.')
    import ctypes as c
    from ctypes import wintypes as w
    class TcpRow(c.Structure):
        _fields_ = [(field, w.DWORD) for field in ('state', 'local', 'lport', 'remote', 'rport')]
    def addr(value):
        return struct.unpack('<I', socket.inet_aton(str(ipaddress.IPv4Address(value))))[0]
    tcp = TcpRow(12, addr(expected[0]), socket.htons(expected[1]),
                 addr(expected[2]), socket.htons(expected[3]))
    api = c.WinDLL('iphlpapi', use_last_error=True)
    api.SetTcpEntry.argtypes = [c.POINTER(TcpRow)]
    api.SetTcpEntry.restype = w.DWORD
    code = api.SetTcpEntry(c.byref(tcp))
    if code:
        raise OperationError(f'SetTcpEntry: Windows {code}. Обычно нужны права администратора.')
    return 'Команда разрыва TCP отправлена. Процесс может подключиться заново; firewall-правило не создавалось.'


def kill_tree(pid: int, created: float) -> str:
    root = checked_process(pid, created, mutation=True)
    children = root.children(recursive=True)
    targets = [(p.pid, p.create_time()) for p in reversed(children)] + [(pid, created)]
    # Preflight the whole snapshot before destructive actions, including own ancestors.
    ancestors = {p.pid for p in psutil.Process().parents()}
    for target, timestamp in targets:
        if target in ancestors:
            raise OperationError('Дерево содержит родителя самого диспетчера. Операция запрещена.')
        checked_process(target, timestamp, mutation=True)
    failed, stopped = [], 0
    for target, timestamp in targets:
        try:
            checked_process(target, timestamp, mutation=True).terminate()
            stopped += 1
        except (psutil.Error, OSError, OperationError) as exc:
            failed.append(f'{target}: {type(exc).__name__}')
    return (f'Завершение дерева: команд принято {stopped}/{len(targets)}. '
            'Это снимок: новые потомки и внешние watchdog могут перезапустить процесс.\n' + '\n'.join(failed))


def safe_delete_path(path: str) -> Path:
    require_windows()
    original = Path(path).absolute()
    target = original.resolve(strict=True)
    if os.path.normcase(str(original)) != os.path.normcase(str(target)):
        raise OperationError('Путь содержит перенаправление или symlink. Удаление отменено.')
    launcher = os.environ.get('OPENTASK_LAUNCHER')
    if launcher and target == Path(launcher).resolve():
        raise OperationError('Удаление запускающего EXE самого диспетчера запрещено.')
    runtime = Path(sys.executable).resolve().parent
    bundle = runtime.parent if runtime.name.casefold() == 'runtime' else runtime
    protected = [bundle, Path(os.environ.get('SystemRoot', r'C:\Windows')).resolve(),
                 Path(sys.executable).resolve().parent,
                 Path(__file__).resolve().parents[1]]
    if target.is_dir() or path.startswith('\\\\') or any(target == root or root in target.parents for root in protected):
        raise OperationError('Удаление системных файлов Windows, файлов диспетчера и сетевых путей запрещено.')
    import ctypes as c
    from ctypes import wintypes as w
    api = c.WinDLL('kernel32', use_last_error=True)
    api.GetFileAttributesW.argtypes = [w.LPCWSTR]
    api.GetFileAttributesW.restype = w.DWORD
    attributes = api.GetFileAttributesW(str(target))
    if attributes == 0xffffffff or attributes & 0x400:
        raise OperationError('Недоступный файл или reparse point: удаление запрещено.')
    return target


def remove_file(pid: int, created: float, reboot: bool = False) -> str:
    p = checked_process(pid, created, mutation=True)
    path = safe_delete_path(p.exe())
    stat = path.stat()
    if reboot:
        import ctypes as c
        from ctypes import wintypes as w
        api = c.WinDLL('kernel32', use_last_error=True)
        api.MoveFileExW.argtypes = [w.LPCWSTR, w.LPCWSTR, w.DWORD]
        api.MoveFileExW.restype = w.BOOL
        if not api.MoveFileExW(str(path), None, 4):
            raise OperationError(f'MoveFileEx: Windows {c.get_last_error()}. Нужны права администратора.')
        return 'Удаление запланировано при перезагрузке: ' + str(path)
    p.terminate()
    try:
        p.wait(timeout=4)
    except psutil.TimeoutExpired:
        raise OperationError('Процесс не завершился. Удаление отменено.') from None
    after = path.stat()
    if (stat.st_size, stat.st_mtime_ns, stat.st_ino) != (after.st_size, after.st_mtime_ns, after.st_ino):
        raise OperationError('Файл изменился после завершения процесса. Удаление отменено.')
    path.unlink()  # Normal Windows ACL/sharing rules apply; no driver or permission bypass.
    return 'Файл удалён без корзины: ' + str(path)


def handles(pid: int, created: float) -> dict:
    require_windows()
    checked_process(pid, created)
    interpreter = Path(sys.executable)
    if interpreter.with_name('python.exe').exists():
        interpreter = interpreter.with_name('python.exe')
    command = ([sys.executable, '--handle-probe', str(pid), str(created)] if getattr(sys, 'frozen', False) else
               [str(interpreter), '-m', 'opentask.handle_probe', str(pid), str(created)])
    timed_out = False
    try:
        result = subprocess.run(command, capture_output=True, timeout=10,
                                creationflags=subprocess.CREATE_NO_WINDOW)
        output = result.stdout
        if result.returncode and not output:
            raise OperationError('Не удалось прочитать дескрипторы: ' + result.stderr.decode('utf-8', 'replace')[-700:])
    except subprocess.TimeoutExpired as exc:
        timed_out, output = True, exc.stdout or b''
    rows = []
    for line in output.decode('utf-8', 'replace').splitlines():
        try:
            rows.append(json.loads(line))
        except ValueError:
            pass
    return {'rows': rows, 'note': ('Сработал 10-секундный лимит; список частичный. ' if timed_out else '') +
            'До 512 дескрипторов File/Key. Наличие дескриптора не доказывает блокировку или изменение. '
            'NT API недокументирован, имена устройств NT не преобразуются в буквы дисков.'}


class RateLimit:
    def __init__(self):
        self.last = float('-inf')

    def acquire(self):
        now = time.monotonic()
        if now - self.last < 16:
            raise OperationError('Подождите 16 секунд между запросами VirusTotal. Лимиты тарифа могут быть строже.')
        self.last = now
