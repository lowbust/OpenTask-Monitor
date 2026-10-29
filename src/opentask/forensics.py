"""On-demand read-only helpers. No key recording, hooks or privilege escalation."""
from __future__ import annotations

import ctypes as c
import json
import os
import subprocess
import sys
from pathlib import Path

from opentask.backend import OperationError, checked_process, require_windows

SENSITIVE = {'SeDebugPrivilege', 'SeImpersonatePrivilege', 'SeTcbPrivilege', 'SeLoadDriverPrivilege',
             'SeBackupPrivilege', 'SeRestorePrivilege', 'SeTakeOwnershipPrivilege', 'SeAssignPrimaryTokenPrivilege'}


def memory_report(pid: int, created: float) -> dict:
    require_windows()
    checked_process(pid, created)
    interpreter = Path(sys.executable)
    if interpreter.with_name('python.exe').exists():
        interpreter = interpreter.with_name('python.exe')
    if getattr(sys, 'frozen', False):
        raise OperationError('Memory helper поддерживается в основном one-EXE release с embedded runtime, не в legacy frozen build.')
    try:
        result = subprocess.run([str(interpreter), '-m', 'opentask.memory_probe', str(pid), str(created)],
                                capture_output=True, timeout=15, creationflags=subprocess.CREATE_NO_WINDOW)
    except subprocess.TimeoutExpired:
        raise OperationError('Memory helper остановлен по пределу 15 секунд. Результат не получен, это не «чисто».') from None
    if result.returncode:
        raise OperationError('Сравнение памяти недоступно: ' + result.stderr.decode('utf-8', 'replace')[-1400:])
    return json.loads(result.stdout.decode('utf-8'))


def token_privileges(pid: int, created: float) -> dict:
    require_windows()
    from ctypes import wintypes as w
    p = checked_process(pid, created)
    k = c.WinDLL('kernel32', use_last_error=True)
    a = c.WinDLL('advapi32', use_last_error=True)
    k.OpenProcess.argtypes = [w.DWORD, w.BOOL, w.DWORD]
    k.OpenProcess.restype = w.HANDLE
    k.CloseHandle.argtypes = [w.HANDLE]
    a.OpenProcessToken.argtypes = [w.HANDLE, w.DWORD, c.POINTER(w.HANDLE)]
    a.OpenProcessToken.restype = w.BOOL
    a.GetTokenInformation.argtypes = [w.HANDLE, c.c_int, c.c_void_p, w.DWORD, c.POINTER(w.DWORD)]
    a.GetTokenInformation.restype = w.BOOL
    class Luid(c.Structure):
        _fields_ = [('low', w.DWORD), ('high', w.LONG)]
    class Privilege(c.Structure):
        _fields_ = [('luid', Luid), ('attributes', w.DWORD)]
    a.LookupPrivilegeNameW.argtypes = [w.LPCWSTR, c.POINTER(Luid), w.LPWSTR, c.POINTER(w.DWORD)]
    a.LookupPrivilegeNameW.restype = w.BOOL
    process = k.OpenProcess(0x1000, False, pid)
    if not process:
        raise c.WinError(c.get_last_error())
    token = w.HANDLE()
    try:
        checked_process(p.pid, created)
        if not a.OpenProcessToken(process, 8, c.byref(token)):
            raise c.WinError(c.get_last_error())
        def info(kind):
            length = w.DWORD()
            a.GetTokenInformation(token, kind, None, 0, c.byref(length))
            if not length.value or length.value > 65536:
                raise OperationError('Token info недоступно или превышает безопасный размер.')
            buffer = c.create_string_buffer(length.value)
            if not a.GetTokenInformation(token, kind, buffer, length, c.byref(length)):
                raise c.WinError(c.get_last_error())
            return buffer
        privileges = info(3)
        count = min(c.cast(privileges, c.POINTER(w.DWORD)).contents.value, 256)
        available = max(0, (len(privileges) - 4) // c.sizeof(Privilege))
        array = c.cast(c.addressof(privileges) + 4, c.POINTER(Privilege))
        rows = []
        for index in range(min(count, available)):
            value = array[index]
            name = c.create_unicode_buffer(512)
            length = w.DWORD(len(name))
            if not a.LookupPrivilegeNameW(None, c.byref(value.luid), name, c.byref(length)):
                label = f'LUID:{value.luid.high}:{value.luid.low}'
            else:
                label = name.value
            enabled = bool(value.attributes & 2)
            rows.append({'Право': label, 'Включено': 'Да' if enabled else 'Нет',
                         'По умолчанию': 'Да' if value.attributes & 1 else 'Нет',
                         'Замечание': 'чувствительное право; не доказательство злоупотребления' if enabled and label in SENSITIVE else ''})
        elevation = info(20)
        elevated = bool(c.cast(elevation, c.POINTER(w.DWORD)).contents.value)
        integrity = 'недоступен'
        try:
            label = info(25)
            sid = c.cast(label, c.POINTER(c.c_void_p)).contents.value
            a.GetSidSubAuthorityCount.argtypes = [c.c_void_p]
            a.GetSidSubAuthorityCount.restype = c.POINTER(w.BYTE)
            a.GetSidSubAuthority.argtypes = [c.c_void_p, w.DWORD]
            a.GetSidSubAuthority.restype = c.POINTER(w.DWORD)
            count_pointer = a.GetSidSubAuthorityCount(sid) if sid else None
            count = count_pointer.contents.value if count_pointer else 0
            if 0 < count <= 15:
                rid = a.GetSidSubAuthority(sid, count - 1).contents.value
                integrity = {0: 'Untrusted', 0x1000: 'Low', 0x2000: 'Medium', 0x2100: 'Medium Plus',
                             0x3000: 'High', 0x4000: 'System', 0x5000: 'Protected'}.get(rid, hex(rid))
        except (OperationError, OSError):
            pass
        return {'elevated': elevated, 'integrity': integrity, 'rows': rows,
                'sensitive_enabled': [row['Право'] for row in rows if row['Замечание']],
                'note': 'Token privileges — снимок. Невозможно определить «необоснованное» повышение только по списку. '
                        'Системным службам и администраторам эти права могут требоваться. Ничего не включалось/не менялось.'}
    finally:
        if token:
            k.CloseHandle(token)
        k.CloseHandle(process)


def gpu_telemetry() -> dict:
    require_windows()
    from ctypes import wintypes as w
    path = Path(os.environ.get('SystemRoot', r'C:\Windows')) / 'System32/nvml.dll'
    if not path.is_file():
        return {'devices': [], 'note': 'NVML не найдена. NVIDIA-телеметрия недоступна; CPU/AMD/Intel power/temp не подставляются фиктивно.'}
    try:
        library = c.WinDLL(str(path))
        library.nvmlInit_v2.restype = c.c_int
        library.nvmlShutdown.restype = c.c_int
        if library.nvmlInit_v2() != 0:
            raise OperationError('NVML не инициализируется. Нужен поддерживаемый NVIDIA driver.')
        try:
            library.nvmlDeviceGetCount_v2.argtypes = [c.POINTER(w.UINT)]
            library.nvmlDeviceGetHandleByIndex_v2.argtypes = [w.UINT, c.POINTER(c.c_void_p)]
            library.nvmlDeviceGetName.argtypes = [c.c_void_p, c.c_char_p, w.UINT]
            library.nvmlDeviceGetTemperature.argtypes = [c.c_void_p, w.UINT, c.POINTER(w.UINT)]
            library.nvmlDeviceGetPowerUsage.argtypes = [c.c_void_p, c.POINTER(w.UINT)]
            class Util(c.Structure):
                _fields_ = [('gpu', w.UINT), ('memory', w.UINT)]
            library.nvmlDeviceGetUtilizationRates.argtypes = [c.c_void_p, c.POINTER(Util)]
            count = w.UINT()
            if library.nvmlDeviceGetCount_v2(c.byref(count)) != 0:
                raise OperationError('NVML: список GPU недоступен.')
            devices = []
            for index in range(min(count.value, 8)):
                handle = c.c_void_p()
                if library.nvmlDeviceGetHandleByIndex_v2(index, c.byref(handle)) != 0:
                    continue
                name = c.create_string_buffer(128)
                library.nvmlDeviceGetName(handle, name, len(name))
                temp, power, util = w.UINT(), w.UINT(), Util()
                tc = library.nvmlDeviceGetTemperature(handle, 0, c.byref(temp))
                pc = library.nvmlDeviceGetPowerUsage(handle, c.byref(power))
                uc = library.nvmlDeviceGetUtilizationRates(handle, c.byref(util))
                devices.append({'name': name.value.decode('utf-8', 'replace'),
                                'temperature_C': temp.value if tc == 0 else None,
                                'power_W': power.value / 1000 if pc == 0 else None,
                                'gpu_percent': util.gpu if uc == 0 else None})
            return {'devices': devices, 'note': 'Физические датчики NVML, если поддерживаются. '
                    'Тепловая инерция и падение нагрузки не доказывают скрытый майнинг; атрибуция по процессам не выполняется.'}
        finally:
            library.nvmlShutdown()
    except (OSError, AttributeError) as exc:
        return {'devices': [], 'note': 'NVML недоступна: ' + str(exc)}
