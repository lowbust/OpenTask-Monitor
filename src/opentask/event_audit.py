"""Read existing Sysmon/Security records, not an API-hooking implementation.

Does not install Sysmon, capture keystrokes, inspect clipboard contents or inject
DLLs. Missing/unconfigured logs must never be interpreted as a clean verdict.
"""
from __future__ import annotations

import ctypes as c
import json
import xml.etree.ElementTree as ET
from ctypes import wintypes as w

from opentask.backend import OperationError, require_windows

SYSMON = 'Microsoft-Windows-Sysmon/Operational'
LABELS = {1: 'Создание процесса', 7: 'Загрузка образа/DLL', 8: 'CreateRemoteThread (Sysmon)',
          10: 'Доступ к процессу (не доказательство WriteProcessMemory)', 11: 'Создание файла',
          12: 'Registry object', 13: 'Registry value', 22: 'DNS-запрос',
          25: 'Process tampering (сообщение Sysmon)'}
SECURITY_LABELS = {4688: 'Создание процесса', 4672: 'Назначение специальных привилегий',
                   4719: 'Изменение политики аудита', 4946: 'Добавление firewall rule',
                   4947: 'Изменение firewall rule', 4948: 'Удаление firewall rule',
                   4950: 'Изменение настроек firewall'}


def parse_event(text, channel):
    root = ET.fromstring(text)
    ns = {'e': 'http://schemas.microsoft.com/win/2004/08/events/event'}
    system = root.find('e:System', ns)
    if system is None:
        raise ValueError('Нет System в событии')
    def value(name):
        node = system.find('e:' + name, ns)
        return node.text if node is not None else ''
    event_id = int(value('EventID') or 0)
    data = {node.get('Name', str(i)): node.text or ''
            for i, node in enumerate(root.findall('e:EventData/e:Data', ns))}
    time = system.find('e:TimeCreated', ns)
    command = str(data.get('CommandLine', '')).casefold()
    phrases = ('vssadmin delete shadows', 'wmic shadowcopy delete', 'wbadmin delete catalog',
               'netsh advfirewall set allprofiles state off', 'recoveryenabled no')
    hint = 'Команда требует ручной проверки; возможно обслуживание/резервное копирование' if any(p in command for p in phrases) else ''
    labels = LABELS if channel == SYSMON else SECURITY_LABELS
    return {'Канал': channel, 'Record': value('EventRecordID'), 'Время UTC': time.get('SystemTime', '') if time is not None else '',
            'ID': event_id, 'Событие': labels.get(event_id, 'Событие'), 'Замечание': hint,
            'Данные': json.dumps(data, ensure_ascii=False)}


def read_events(channel=SYSMON, minutes=10, maximum=200):
    require_windows()
    if channel not in (SYSMON, 'Security'):
        raise ValueError('Канал не разрешён')
    library = c.WinDLL('wevtapi', use_last_error=True)
    library.EvtQuery.argtypes = [w.HANDLE, w.LPCWSTR, w.LPCWSTR, w.DWORD]
    library.EvtQuery.restype = w.HANDLE
    library.EvtNext.argtypes = [w.HANDLE, w.DWORD, c.POINTER(w.HANDLE), w.DWORD, w.DWORD, c.POINTER(w.DWORD)]
    library.EvtNext.restype = w.BOOL
    library.EvtRender.argtypes = [w.HANDLE, w.HANDLE, w.DWORD, w.DWORD, c.c_void_p,
                                  c.POINTER(w.DWORD), c.POINTER(w.DWORD)]
    library.EvtRender.restype = w.BOOL
    library.EvtClose.argtypes = [w.HANDLE]
    ids = LABELS if channel == SYSMON else SECURITY_LABELS
    query = '*[System[(' + ' or '.join(f'EventID={i}' for i in ids) + f') and TimeCreated[timediff(@SystemTime)<={minutes * 60000}]]]'
    handle = library.EvtQuery(None, channel, query, 0x201)
    if not handle:
        raise OperationError(f'Журнал {channel} недоступен, Windows {c.get_last_error()}. '
                             'Нужны установленный/настроенный Sysmon либо включённый аудит и права. Это не означает отсутствие активности.')
    rows = []
    try:
        while len(rows) < maximum:
            events = (w.HANDLE * 16)()
            returned = w.DWORD()
            if not library.EvtNext(handle, 16, events, 0, 0, c.byref(returned)):
                code = c.get_last_error()
                if code in (259, 1460):
                    break
                raise OperationError(f'EvtNext Windows {code}')
            try:
                for event in events[:returned.value]:
                    size, properties = w.DWORD(), w.DWORD()
                    library.EvtRender(None, event, 1, 0, None, c.byref(size), c.byref(properties))
                    if size.value <= 0 or size.value > 2_000_000:
                        continue
                    buffer = c.create_unicode_buffer(size.value // c.sizeof(c.c_wchar) + 1)
                    if library.EvtRender(None, event, 1, c.sizeof(buffer), buffer, c.byref(size), c.byref(properties)):
                        rows.append(parse_event(buffer.value, channel))
                    if len(rows) >= maximum:
                        break
            finally:
                for event in events[:returned.value]:
                    library.EvtClose(event)
    finally:
        library.EvtClose(handle)
    return rows
