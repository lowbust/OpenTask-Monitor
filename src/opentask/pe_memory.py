"""PE executable-section comparison helpers. No process writes/injection/hooks.

Loader relocations and IAT ranges are accounted for. Remaining differences can
still be legitimate hotpatching/instrumentation/JIT; this is not a malware verdict.
"""
from __future__ import annotations

import struct
from dataclasses import dataclass


@dataclass(frozen=True)
class Section:
    name: str
    rva: int
    virtual_size: int
    raw: int
    raw_size: int
    flags: int


class PE:
    def __init__(self, data: bytes):
        self.data = data
        if len(data) < 0x100 or data[:2] != b'MZ':
            raise ValueError('Not a PE file')
        nt = self.u32(0x3c)
        if nt + 24 > len(data) or data[nt:nt + 4] != b'PE\0\0':
            raise ValueError('Invalid PE header')
        self.machine = self.u16(nt + 4)
        count, optional_size = self.u16(nt + 6), self.u16(nt + 20)
        if not 0 < count <= 96:
            raise ValueError('Unsupported section count')
        optional = nt + 24
        magic = self.u16(optional)
        if magic not in (0x10b, 0x20b) or self.machine not in (0x14c, 0x8664):
            raise ValueError('Only PE x86/x64 supported')
        self.bits = 64 if magic == 0x20b else 32
        self.image_base = self.u64(optional + 24) if self.bits == 64 else self.u32(optional + 28)
        self.image_size = self.u32(optional + 56)
        self.entry = self.u32(optional + 16)
        directory = optional + (112 if self.bits == 64 else 96)
        directories = min(self.u32(optional + (108 if self.bits == 64 else 92)), 16)
        self.directories = []
        for index in range(directories):
            at = directory + index * 8
            if at + 8 > optional + optional_size:
                break
            self.directories.append((self.u32(at), self.u32(at + 4)))
        self.sections = []
        table = optional + optional_size
        if table + count * 40 > len(data):
            raise ValueError('Truncated section table')
        for index in range(count):
            at = table + index * 40
            section = Section(data[at:at + 8].split(b'\0')[0].decode('ascii', 'replace'),
                              self.u32(at + 12), self.u32(at + 8), self.u32(at + 20),
                              self.u32(at + 16), self.u32(at + 36))
            if section.raw + section.raw_size > len(data):
                raise ValueError('Truncated PE section')
            self.sections.append(section)

    def u16(self, at):
        return struct.unpack_from('<H', self.data, at)[0]

    def u32(self, at):
        return struct.unpack_from('<I', self.data, at)[0]

    def u64(self, at):
        return struct.unpack_from('<Q', self.data, at)[0]

    def directory(self, index):
        return self.directories[index] if index < len(self.directories) else (0, 0)

    def offset(self, rva):
        for section in self.sections:
            if section.rva <= rva < section.rva + section.raw_size:
                return section.raw + rva - section.rva
        raise ValueError('RVA not present on disk')

    def relocations(self):
        rva, size = self.directory(5)
        if not rva or not size:
            return []
        if size > 2 * 1024 * 1024:
            raise ValueError('Relocation directory exceeds 2 MiB scan limit')
        start = self.offset(rva)
        end = min(start + size, len(self.data))
        result = []
        while start + 8 <= end:
            page, block = self.u32(start), self.u32(start + 4)
            if block < 8 or start + block > end:
                raise ValueError('Malformed relocation block')
            for at in range(start + 8, start + block, 2):
                entry = self.u16(at)
                kind, relative = entry >> 12, entry & 0xfff
                if kind in (3, 10):
                    if len(result) >= 100000:
                        raise ValueError('Relocation entry scan limit exceeded')
                    result.append((page + relative, 4 if kind == 3 else 8))
                elif kind != 0:
                    # Cannot claim a trustworthy baseline if relocation types are unknown.
                    raise ValueError(f'Unsupported relocation type {kind}')
            start += block
        return result

    def expected_code(self, actual_base: int, limit: int = 32 * 1024 * 1024):
        relocations = self.relocations()
        delta = actual_base - self.image_base
        remaining = limit
        for section in self.sections:
            if not section.flags & 0x20000000 or not section.raw_size:
                continue
            length = min(section.raw_size, section.virtual_size or section.raw_size,
                         max(0, self.image_size - section.rva), remaining)
            if length <= 0:
                continue
            expected = bytearray(self.data[section.raw:section.raw + length])
            for rva, width in relocations:
                offset = rva - section.rva
                if 0 <= offset <= len(expected) - width:
                    value = int.from_bytes(expected[offset:offset + width], 'little')
                    expected[offset:offset + width] = ((value + delta) % (1 << (width * 8))).to_bytes(width, 'little')
            remaining -= length
            yield section, bytes(expected)


def code_difference(expected: bytes, actual: bytes, rva: int, ignored: tuple[int, int] = (0, 0)):
    start, length = ignored
    compared, changed, offsets = 0, 0, []
    for i, (wanted, found) in enumerate(zip(expected, actual)):
        address = rva + i
        if length and start <= address < start + length:
            continue
        compared += 1
        if wanted != found:
            changed += 1
            if len(offsets) < 32:
                offsets.append(hex(address))
    return compared, changed, offsets
