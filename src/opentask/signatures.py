"""Offline Authenticode verification (embedded and Windows catalog signatures).

Trust is Windows' local policy, not a malware verdict; online revocation is disabled.
This module never verifies from the GUI thread. Results are cached by file identity.
"""
from __future__ import annotations

import ctypes as c
import os
import uuid
from dataclasses import dataclass
from functools import lru_cache


@dataclass(frozen=True)
class Signature:
    status: str
    publisher: str = ''
    code: int = 0


def verify_signature(path: str) -> Signature:
    if os.name != 'nt':
        return Signature('только Windows')
    try:
        stat = os.stat(path)
        return _verify_cached(path, stat.st_size, stat.st_mtime_ns)
    except OSError as exc:
        return Signature('недоступна', code=exc.errno or 0)


@lru_cache(maxsize=2048)
def _verify_cached(path: str, size: int, modified: int) -> Signature:
    from ctypes import wintypes as w

    class FileInfo(c.Structure):
        _fields_ = [('cb', w.DWORD), ('path', w.LPCWSTR), ('handle', w.HANDLE), ('subject', c.c_void_p)]

    class CatalogInfo(c.Structure):
        _fields_ = [('cb', w.DWORD), ('version', w.DWORD), ('catalog', w.LPCWSTR),
                    ('tag', w.LPCWSTR), ('path', w.LPCWSTR), ('handle', w.HANDLE),
                    ('hash', c.c_void_p), ('length', w.DWORD), ('context', c.c_void_p), ('admin', w.HANDLE)]

    class Choice(c.Union):
        _fields_ = [('file', c.POINTER(FileInfo)), ('catalog', c.POINTER(CatalogInfo))]

    class TrustData(c.Structure):
        _anonymous_ = ('choice',)
        _fields_ = [('cb', w.DWORD), ('policy', c.c_void_p), ('sip', c.c_void_p),
                    ('ui', w.DWORD), ('revocation', w.DWORD), ('kind', w.DWORD), ('choice', Choice),
                    ('action', w.DWORD), ('state', w.HANDLE), ('url', w.LPWSTR),
                    ('flags', w.DWORD), ('context', w.DWORD), ('settings', c.c_void_p)]

    class Signer(c.Structure):
        _fields_ = [('cb', w.DWORD), ('time', w.FILETIME), ('count', w.DWORD), ('certs', c.c_void_p)]

    class Cert(c.Structure):
        _fields_ = [('cb', w.DWORD), ('cert', c.c_void_p)]

    wintrust = c.WinDLL('wintrust', use_last_error=True)
    crypt = c.WinDLL('crypt32', use_last_error=True)
    kernel = c.WinDLL('kernel32', use_last_error=True)
    guid = c.create_string_buffer(uuid.UUID('00aac56b-cd44-11d0-8cc2-00c04fc295ee').bytes_le)
    wintrust.WinVerifyTrust.argtypes = [w.HWND, c.c_void_p, c.POINTER(TrustData)]
    wintrust.WinVerifyTrust.restype = w.LONG
    wintrust.WTHelperProvDataFromStateData.argtypes = [w.HANDLE]
    wintrust.WTHelperProvDataFromStateData.restype = c.c_void_p
    wintrust.WTHelperGetProvSignerFromChain.argtypes = [c.c_void_p, w.DWORD, w.BOOL, w.DWORD]
    wintrust.WTHelperGetProvSignerFromChain.restype = c.POINTER(Signer)
    crypt.CertGetNameStringW.argtypes = [c.c_void_p, w.DWORD, w.DWORD, c.c_void_p, w.LPWSTR, w.DWORD]
    crypt.CertGetNameStringW.restype = w.DWORD

    def check(data):
        data.cb = c.sizeof(data)
        data.ui = 2  # WTD_UI_NONE
        data.action = 1  # VERIFY; always CLOSE in finally
        data.flags = 0x1000 | 0x10  # CACHE_ONLY_URL_RETRIEVAL | REVOCATION_CHECK_NONE
        publisher = ''
        try:
            code = wintrust.WinVerifyTrust(None, guid, c.byref(data)) & 0xffffffff
            if not code and data.state:
                provider = wintrust.WTHelperProvDataFromStateData(data.state)
                signer = wintrust.WTHelperGetProvSignerFromChain(provider, 0, False, 0) if provider else None
                if signer and signer.contents.count and signer.contents.certs:
                    cert = c.cast(signer.contents.certs, c.POINTER(Cert)).contents.cert
                    buffer = c.create_unicode_buffer(1024)
                    crypt.CertGetNameStringW(cert, 4, 0, None, buffer, len(buffer))
                    publisher = buffer.value
            return code, publisher
        finally:
            data.action = 2
            wintrust.WinVerifyTrust(None, guid, c.byref(data))

    file = FileInfo(c.sizeof(FileInfo), path, None, None)
    data = TrustData()
    data.kind, data.file = 1, c.pointer(file)
    code, publisher = check(data)
    if code in (0x800B0100, 0x800B0003, 0x800B0001):
        # Catalog-only Windows executables must not be called "unsigned" without checking catalogs.
        admin = w.HANDLE()
        handle = None
        catalog = None
        try:
            wintrust.CryptCATAdminAcquireContext2.argtypes = [c.POINTER(w.HANDLE), c.c_void_p,
                                                             w.LPCWSTR, c.c_void_p, w.DWORD]
            wintrust.CryptCATAdminAcquireContext2.restype = w.BOOL
            wintrust.CryptCATAdminCalcHashFromFileHandle2.argtypes = [w.HANDLE, w.HANDLE,
                                                                    c.POINTER(w.DWORD), c.c_void_p, w.DWORD]
            wintrust.CryptCATAdminCalcHashFromFileHandle2.restype = w.BOOL
            wintrust.CryptCATAdminEnumCatalogFromHash.argtypes = [w.HANDLE, c.c_void_p, w.DWORD,
                                                                w.DWORD, c.POINTER(w.HANDLE)]
            wintrust.CryptCATAdminEnumCatalogFromHash.restype = w.HANDLE
            wintrust.CryptCATAdminReleaseCatalogContext.argtypes = [w.HANDLE, w.HANDLE, w.DWORD]
            wintrust.CryptCATAdminReleaseContext.argtypes = [w.HANDLE, w.DWORD]
            kernel.CreateFileW.argtypes = [w.LPCWSTR, w.DWORD, w.DWORD, c.c_void_p,
                                          w.DWORD, w.DWORD, w.HANDLE]
            kernel.CreateFileW.restype = w.HANDLE
            kernel.CloseHandle.argtypes = [w.HANDLE]
            if not wintrust.CryptCATAdminAcquireContext2(c.byref(admin), None, 'SHA256', None, 0):
                return Signature('каталожная проверка недоступна', code=code)
            handle = kernel.CreateFileW(path, 0x80000000, 7, None, 3, 0x80, None)
            if handle == c.c_void_p(-1).value:
                return Signature('недоступна', code=code)
            length = w.DWORD()
            wintrust.CryptCATAdminCalcHashFromFileHandle2(admin, handle, c.byref(length), None, 0)
            if not length.value or length.value > 1024:
                return Signature('каталожная проверка недоступна', code=code)
            digest = (c.c_ubyte * length.value)()
            if not wintrust.CryptCATAdminCalcHashFromFileHandle2(admin, handle, c.byref(length), digest, 0):
                return Signature('каталожная проверка недоступна', code=code)
            catalog = wintrust.CryptCATAdminEnumCatalogFromHash(admin, digest, length, 0, None)
            if catalog:
                class CatInfo(c.Structure):
                    _fields_ = [('cb', w.DWORD), ('path', w.WCHAR * 260)]
                info = CatInfo(c.sizeof(CatInfo))
                wintrust.CryptCATCatalogInfoFromContext.argtypes = [w.HANDLE, c.POINTER(CatInfo), w.DWORD]
                wintrust.CryptCATCatalogInfoFromContext.restype = w.BOOL
                if wintrust.CryptCATCatalogInfoFromContext(catalog, c.byref(info), 0):
                    cat = CatalogInfo(c.sizeof(CatalogInfo), 0, info.path, bytes(digest).hex().upper(),
                                      path, handle, c.cast(digest, c.c_void_p), length.value, None, admin)
                    data = TrustData()
                    data.kind, data.catalog = 2, c.pointer(cat)
                    code, publisher = check(data)
        except (OSError, AttributeError):
            return Signature('каталожная проверка недоступна', code=code)
        finally:
            if catalog:
                wintrust.CryptCATAdminReleaseCatalogContext(admin, catalog, 0)
            if handle and handle != c.c_void_p(-1).value:
                kernel.CloseHandle(handle)
            if admin:
                wintrust.CryptCATAdminReleaseContext(admin, 0)
    if code == 0:
        label = 'Microsoft: доверена' if publisher.casefold() in {
            'microsoft corporation', 'microsoft windows', 'microsoft windows publisher'} else 'подпись доверена'
        return Signature(label, publisher)
    if code == 0x800B0100:
        return Signature('подпись не найдена', code=code)
    if code == 0x80096010:
        return Signature('подпись недействительна', code=code)
    return Signature('подпись не доверена', publisher, code)
