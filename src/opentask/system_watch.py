"""Read-only polling of hosts/DNS/IFEO. Detects changes, not responsible processes.

This is NOT write prevention. DHCP, VPN, debuggers and administration can produce
legitimate changes. No repair/deletion is performed automatically.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path

from opentask.backend import require_windows

IFEO_APPS = ('regedit.exe', 'cmd.exe', 'taskmgr.exe', 'powershell.exe', 'pwsh.exe', 'mmc.exe', 'taskkill.exe')
IFEO = r'Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options'


def registry_value(value):
    if isinstance(value, bytes):
        return {'binary_hex': value[:4096].hex(), 'size': len(value)}
    if isinstance(value, str):
        return value[:32768]
    if isinstance(value, list):
        return [registry_value(item) for item in value[:128]]
    return value


def read_state():
    require_windows()
    import winreg as reg
    state = {'hosts': {}, 'dns': {}, 'ifeo': [], 'errors': []}
    hosts = Path(os.environ.get('SystemRoot', r'C:\Windows')) / 'System32/drivers/etc/hosts'
    try:
        if hosts.stat().st_size > 16 * 1024 * 1024:
            raise ValueError('hosts превышает 16 МиБ, хеширование пропущено')
        content = hosts.read_bytes()
        state['hosts'] = {'path': str(hosts), 'sha256': hashlib.sha256(content).hexdigest(), 'size': len(content)}
    except (OSError, ValueError) as exc:
        state['errors'].append('hosts: ' + str(exc))
    for family in ('Tcpip', 'Tcpip6'):
        base = rf'SYSTEM\CurrentControlSet\Services\{family}\Parameters'
        paths = [base]
        try:
            with reg.OpenKey(reg.HKEY_LOCAL_MACHINE, base + r'\Interfaces', 0, reg.KEY_READ) as root:
                for index in range(reg.QueryInfoKey(root)[0]):
                    paths.append(base + '\\Interfaces\\' + reg.EnumKey(root, index))
        except OSError as exc:
            state['errors'].append(f'{family}: {exc}')
        for path in paths:
            try:
                with reg.OpenKey(reg.HKEY_LOCAL_MACHINE, path) as key:
                    values = {}
                    for name in ('NameServer', 'DhcpNameServer', 'Domain', 'DhcpDomain', 'SearchList'):
                        try:
                            values[name] = registry_value(reg.QueryValueEx(key, name)[0])
                        except FileNotFoundError:
                            pass
                    state['dns'][path] = values
            except OSError:
                continue
    for view, label in ((reg.KEY_WOW64_64KEY, '64'), (reg.KEY_WOW64_32KEY, '32')):
        for name in IFEO_APPS:
            try:
                with reg.OpenKey(reg.HKEY_LOCAL_MACHINE, IFEO + '\\' + name, 0, reg.KEY_READ | view) as key:
                    row = {'view': label, 'image': name}
                    for value in ('Debugger', 'GlobalFlag', 'UseFilter'):
                        try:
                            row[value] = registry_value(reg.QueryValueEx(key, value)[0])
                        except FileNotFoundError:
                            pass
                    state['ifeo'].append(row)
            except FileNotFoundError:
                continue
            except OSError as exc:
                state['errors'].append(f'IFEO {name}: {exc}')
    return state


def changes(old, new):
    if old is None:
        return []
    result = []
    for group in ('hosts', 'dns', 'ifeo'):
        if old.get(group) != new.get(group):
            result.append({'Область': group, 'Событие': 'Изменение требует проверки',
                           'До': json.dumps(old.get(group), ensure_ascii=False)[:2000],
                           'После': json.dumps(new.get(group), ensure_ascii=False)[:2000],
                           'Примечание': 'Ответственный процесс не установлен. Изменение может быть легитимным.'})
    return result
