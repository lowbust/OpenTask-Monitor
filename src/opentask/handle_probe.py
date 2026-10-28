"""Isolated, time-bounded NT handle enumeration helper. Read-only, Windows x64.

NtQueryObject on some File handles can hang. The parent kills this helper after
10 seconds, preserving complete JSONL rows already returned. No handle is closed
in the target process; only our duplicates are closed.
"""
from __future__ import annotations

import ctypes as c
import json
import sys
from ctypes import wintypes as w

from opentask.backend import checked_process, require_windows


def main():
    require_windows()
    pid, created = int(sys.argv[1]), float(sys.argv[2])
    checked_process(pid, created)
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')
    nt = c.WinDLL('ntdll')
    kernel = c.WinDLL('kernel32', use_last_error=True)
    kernel.OpenProcess.argtypes = [w.DWORD, w.BOOL, w.DWORD]
    kernel.OpenProcess.restype = w.HANDLE
    kernel.GetCurrentProcess.restype = w.HANDLE
    kernel.DuplicateHandle.argtypes = [w.HANDLE, w.HANDLE, w.HANDLE, c.POINTER(w.HANDLE),
                                       w.DWORD, w.BOOL, w.DWORD]
    kernel.DuplicateHandle.restype = w.BOOL
    kernel.CloseHandle.argtypes = [w.HANDLE]
    nt.NtQuerySystemInformation.argtypes = [w.ULONG, c.c_void_p, w.ULONG, c.POINTER(w.ULONG)]
    nt.NtQuerySystemInformation.restype = w.LONG
    nt.NtQueryObject.argtypes = [w.HANDLE, w.ULONG, c.c_void_p, w.ULONG, c.POINTER(w.ULONG)]
    nt.NtQueryObject.restype = w.LONG

    class Header(c.Structure):
        _fields_ = [('count', c.c_size_t), ('reserved', c.c_size_t)]

    class Entry(c.Structure):
        _fields_ = [('object', c.c_void_p), ('pid', c.c_size_t), ('handle', c.c_size_t),
                    ('access', w.ULONG), ('trace', w.USHORT), ('type', w.USHORT),
                    ('attributes', w.ULONG), ('reserved', w.ULONG)]

    class Unicode(c.Structure):
        _fields_ = [('length', w.USHORT), ('maximum', w.USHORT), ('buffer', c.c_void_p)]

    required = w.ULONG()
    size = 1024 * 1024
    while size <= 64 * 1024 * 1024:
        buffer = c.create_string_buffer(size)
        status = nt.NtQuerySystemInformation(64, buffer, size, c.byref(required))
        if status == 0:
            break
        if status & 0xffffffff != 0xc0000004:
            raise OSError(f'NtQuerySystemInformation: 0x{status & 0xffffffff:08X}')
        size = max(size * 2, required.value + 65536)
    else:
        raise OSError('Handle table exceeds 64 MiB safety limit')
    process = kernel.OpenProcess(0x40, False, pid)
    if not process:
        raise c.WinError(c.get_last_error())

    def query(handle, kind):
        text = c.create_string_buffer(65536)
        length = w.ULONG()
        if nt.NtQueryObject(handle, kind, text, len(text), c.byref(length)) != 0:
            return ''
        value = c.cast(text, c.POINTER(Unicode)).contents
        if value.length > 32766 or not value.buffer:
            return ''
        return c.wstring_at(value.buffer, value.length // 2)

    types = {}
    emitted = 0
    try:
        count = min(c.cast(buffer, c.POINTER(Header)).contents.count,
                    (size - c.sizeof(Header)) // c.sizeof(Entry))
        array = c.cast(c.addressof(buffer) + c.sizeof(Header), c.POINTER(Entry))
        for i in range(count):
            entry = array[i]
            if entry.pid != pid:
                continue
            duplicate = w.HANDLE()
            if not kernel.DuplicateHandle(process, entry.handle, kernel.GetCurrentProcess(),
                                          c.byref(duplicate), 0, False, 2):
                continue
            try:
                if entry.type not in types:
                    types[entry.type] = query(duplicate, 2)
                kind = types[entry.type]
                if kind not in ('File', 'Key'):
                    continue
                name = query(duplicate, 1)
                print(json.dumps({'Handle': hex(entry.handle), 'Тип': kind, 'Имя NT': name or '(без имени)',
                                  'Access': hex(entry.access)}, ensure_ascii=False), flush=True)
                emitted += 1
                if emitted >= 512:
                    break
            finally:
                kernel.CloseHandle(duplicate)
    finally:
        kernel.CloseHandle(process)


if __name__ == '__main__':
    main()
