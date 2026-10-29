"""Read-only isolated Windows memory/thread inspection; parent enforces a timeout.

Only PROCESS_VM_READ / QUERY and THREAD_QUERY are requested. No DLL injection,
WriteProcessMemory, thread suspension, API hook installation or key recording.
"""
from __future__ import annotations

import ctypes as c
import json
import sys
import time
from ctypes import wintypes as w
from pathlib import Path

from opentask.backend import OperationError, checked_process, require_windows
from opentask.pe_memory import PE, code_difference


class NativeProcess:
    def __init__(self, pid, created):
        require_windows()
        self.process = checked_process(pid, created)
        self.kernel = c.WinDLL('kernel32', use_last_error=True)
        self.psapi = c.WinDLL('psapi', use_last_error=True)
        self.nt = c.WinDLL('ntdll')
        k = self.kernel
        k.OpenProcess.argtypes = [w.DWORD, w.BOOL, w.DWORD]
        k.OpenProcess.restype = w.HANDLE
        k.CloseHandle.argtypes = [w.HANDLE]
        k.ReadProcessMemory.argtypes = [w.HANDLE, c.c_void_p, c.c_void_p, c.c_size_t, c.POINTER(c.c_size_t)]
        k.ReadProcessMemory.restype = w.BOOL
        k.GetProcessTimes.argtypes = [w.HANDLE, c.POINTER(w.FILETIME), c.POINTER(w.FILETIME),
                                     c.POINTER(w.FILETIME), c.POINTER(w.FILETIME)]
        self.handle = k.OpenProcess(0x410, False, pid)
        if not self.handle:
            raise c.WinError(c.get_last_error())
        times = [w.FILETIME() for _ in range(4)]
        if not k.GetProcessTimes(self.handle, *[c.byref(value) for value in times]):
            k.CloseHandle(self.handle)
            raise OperationError('Не удалось проверить время создания открытого процесса.')
        ticks = (times[0].dwHighDateTime << 32) | times[0].dwLowDateTime
        if abs((ticks - 116444736000000000) / 10_000_000 - created) > 0.002:
            k.CloseHandle(self.handle)
            raise OperationError('PID изменился до открытия process handle.')

    def close(self):
        self.kernel.CloseHandle(self.handle)

    def read(self, address, length):
        buffer = c.create_string_buffer(length)
        read = c.c_size_t()
        if not self.kernel.ReadProcessMemory(self.handle, address, buffer, length, c.byref(read)):
            return b''
        return buffer.raw[:read.value]

    def modules(self):
        class Info(c.Structure):
            _fields_ = [('base', c.c_void_p), ('size', w.DWORD), ('entry', c.c_void_p)]
        p = self.psapi
        p.EnumProcessModulesEx.argtypes = [w.HANDLE, c.POINTER(w.HMODULE), w.DWORD, c.POINTER(w.DWORD), w.DWORD]
        p.EnumProcessModulesEx.restype = w.BOOL
        p.GetModuleInformation.argtypes = [w.HANDLE, w.HMODULE, c.POINTER(Info), w.DWORD]
        p.GetModuleInformation.restype = w.BOOL
        p.GetModuleFileNameExW.argtypes = [w.HANDLE, w.HMODULE, w.LPWSTR, w.DWORD]
        modules = (w.HMODULE * 2048)()
        size = w.DWORD()
        if not p.EnumProcessModulesEx(self.handle, modules, c.sizeof(modules), c.byref(size), 3):
            raise c.WinError(c.get_last_error())
        result = []
        for module in modules[:min(size.value // c.sizeof(w.HMODULE), 2048)]:
            info = Info()
            path = c.create_unicode_buffer(32768)
            if p.GetModuleInformation(self.handle, module, c.byref(info), c.sizeof(info)):
                p.GetModuleFileNameExW(self.handle, module, path, len(path))
                result.append({'base': info.base or 0, 'size': info.size, 'path': path.value})
        return result

    def peb_base(self):
        k, nt = self.kernel, self.nt
        k.IsWow64Process.argtypes = [w.HANDLE, c.POINTER(w.BOOL)]
        wow = w.BOOL()
        k.IsWow64Process(self.handle, c.byref(wow))
        nt.NtQueryInformationProcess.argtypes = [w.HANDLE, w.ULONG, c.c_void_p, w.ULONG, c.POINTER(w.ULONG)]
        nt.NtQueryInformationProcess.restype = w.LONG
        size = w.ULONG()
        if wow:
            pointer = c.c_size_t()
            code = nt.NtQueryInformationProcess(self.handle, 26, c.byref(pointer), c.sizeof(pointer), c.byref(size))
            address, width, offset = pointer.value, 4, 8
        else:
            values = (c.c_void_p * 6)()
            code = nt.NtQueryInformationProcess(self.handle, 0, values, c.sizeof(values), c.byref(size))
            address, width, offset = values[1] or 0, 8, 16
        if code != 0 or not address:
            return 0
        data = self.read(address + offset, width)
        return int.from_bytes(data, 'little') if len(data) == width else 0

    def memory_info(self, address):
        class MBI(c.Structure):
            _fields_ = [('base', c.c_void_p), ('allocation', c.c_void_p), ('allocation_protect', w.DWORD),
                        ('partition', w.WORD), ('size', c.c_size_t), ('state', w.DWORD),
                        ('protect', w.DWORD), ('type', w.DWORD)]
        self.kernel.VirtualQueryEx.argtypes = [w.HANDLE, c.c_void_p, c.POINTER(MBI), c.c_size_t]
        self.kernel.VirtualQueryEx.restype = c.c_size_t
        info = MBI()
        if not self.kernel.VirtualQueryEx(self.handle, address, c.byref(info), c.sizeof(info)):
            return None
        return info


def inspect_memory(pid: int, created: float) -> dict:
    native = NativeProcess(pid, created)
    notes = ['Только x86/x64. Различия кода могут быть легитимными hotpatch/hooks/AV; это не вердикт hollowing.',
             'Пределы: executable sections 32 МиБ, regions 16384/private results 128, modules 2048, threads 1024; частичный охват.',
             'Перечисленные потоки — не все возможные скрытые/DKOM потоки. Private executable память встречается у JIT/.NET/браузеров.']
    try:
        modules = native.modules()
        if not modules:
            raise OperationError('Список модулей недоступен, сравнение невозможно.')
        image = modules[0]
        peb = native.peb_base()
        file = native.process.exe()
        before = Path(file).stat()
        if before.st_size > 256 * 1024 * 1024:
            raise OperationError('EXE больше 256 МиБ: предел безопасного read-only сканирования.')
        with Path(file).open('rb') as stream:
            disk = stream.read(256 * 1024 * 1024 + 1)
        if len(disk) > 256 * 1024 * 1024:
            raise OperationError('EXE вырос сверх предела 256 МиБ.')
        after = Path(file).stat()
        if (before.st_size, before.st_mtime_ns, before.st_ino) != (after.st_size, after.st_mtime_ns, after.st_ino):
            raise OperationError('EXE на диске изменился во время чтения; сравнение отменено.')
        pe = PE(disk)
        compared = changed = unreadable = 0
        sections = []
        scan_start = time.monotonic()
        for section, expected in pe.expected_code(image['base']):
            ncompared = nchanged = 0
            offsets = []
            for offset in range(0, len(expected), 4096):
                if time.monotonic() - scan_start > 5:
                    notes.append('Достигнут предел 5 с для сравнения секций; результат частичный.')
                    break
                wanted = expected[offset:offset + 4096]
                actual = native.read(image['base'] + section.rva + offset, len(wanted))
                if len(actual) != len(wanted):
                    unreadable += len(wanted)
                    continue
                count, diff, locations = code_difference(wanted, actual, section.rva + offset, pe.directory(12))
                ncompared += count
                nchanged += diff
                offsets.extend(locations[:max(0, 32 - len(offsets))])
            sections.append({'section': section.name, 'compared': ncompared, 'changed': nchanged,
                             'example_RVA': offsets})
            compared += ncompared
            changed += nchanged
        regions = []
        address = 0
        for _ in range(16384):
            if time.monotonic() - scan_start > 7:
                notes.append('Обход регионов ограничен общим временем; список может быть неполным.')
                break
            info = native.memory_info(address)
            if info is None or not info.size:
                break
            if info.state == 0x1000 and info.type == 0x20000 and info.protect & 0xf0 and not info.protect & 0x100:
                if len(regions) < 128:
                    regions.append({'base': hex(info.base or 0), 'size': info.size, 'protect': hex(info.protect)})
            following = (info.base or 0) + info.size
            if following <= address:
                break
            address = following
        else:
            notes.append('Достигнут предел числа регионов; обход частичный.')
        threads = []
        k, nt = native.kernel, native.nt
        k.OpenThread.argtypes = [w.DWORD, w.BOOL, w.DWORD]
        k.OpenThread.restype = w.HANDLE
        nt.NtQueryInformationThread.argtypes = [w.HANDLE, w.ULONG, c.c_void_p, w.ULONG, c.POINTER(w.ULONG)]
        nt.NtQueryInformationThread.restype = w.LONG
        for thread in native.process.threads()[:1024]:
            handle = k.OpenThread(0x40, False, thread.id)
            if not handle:
                threads.append({'tid': thread.id, 'note': 'нет доступа к адресу старта'})
                continue
            try:
                start = c.c_void_p()
                length = w.ULONG()
                code = nt.NtQueryInformationThread(handle, 9, c.byref(start), c.sizeof(start), c.byref(length))
                value = start.value or 0
                if code != 0 or not value:
                    threads.append({'tid': thread.id, 'note': 'адрес старта недоступен'})
                    continue
                module = next((m['path'] for m in modules if m['base'] <= value < m['base'] + m['size']), '')
                info = native.memory_info(value)
                outside = not module
                threads.append({'tid': thread.id, 'start': hex(value), 'module': module or '(вне перечисленных модулей)',
                                'outside_module': outside,
                                'memory_note': ('нет информации об участке' if info is None else
                                    ('не MEM_COMMIT: адрес может относиться к уже завершённому/изменённому потоку'
                                     if info.state != 0x1000 else 'MEM_COMMIT на момент проверки')),
                                'state': hex(info.state) if info else 'недоступно',
                                'type': hex(info.type) if info else 'недоступно'})
            finally:
                k.CloseHandle(handle)
        return {'pid': pid, 'process_created': created, 'checked_at': time.time(),
                'file': file, 'main_module': image, 'PEB_image_base': hex(peb),
                'PEB_module_mismatch': bool(peb and peb != image['base']), 'bits': pe.bits,
                'disk_image_size': pe.image_size, 'disk_entry_RVA': hex(pe.entry),
                'compared_bytes': compared, 'different_bytes': changed,
                'different_percent': round(100 * changed / compared, 3) if compared else None,
                'unreadable_bytes': unreadable, 'sections': sections,
                'private_executable_regions': regions, 'threads': threads,
                'thread_outside_count': sum(t.get('outside_module', False) for t in threads), 'notes': notes}
    finally:
        native.close()


def main():
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')
    result = inspect_memory(int(sys.argv[1]), float(sys.argv[2]))
    print(json.dumps(result, ensure_ascii=False), flush=True)


if __name__ == '__main__':
    main()
