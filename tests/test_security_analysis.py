"""New feature tests use fixtures/mocks; never stop real processes or edit registry."""
from __future__ import annotations

import hashlib
import json
import struct
import zipfile
from dataclasses import asdict, replace
from types import SimpleNamespace

import pytest

from opentask import event_audit, quarantine, snapshots, system_watch
from opentask.backend import OperationError
from opentask.core import ProcessRow
from opentask.pe_memory import PE, code_difference
from opentask.signatures import Signature
from opentask.triage import priority


def row(**kwargs):
    base = ProcessRow(10, 1, 'example.exe', 'user', 0, 1024, 1, 'running', 123,
                      r'C:\Apps\example.exe')
    return replace(base, **kwargs)


def pe_fixture(bits=64):
    data = bytearray(0x800)
    data[:2] = b'MZ'
    struct.pack_into('<I', data, 0x3c, 0x80)
    data[0x80:0x84] = b'PE\0\0'
    machine, size, magic = (0x8664, 0xf0, 0x20b) if bits == 64 else (0x14c, 0xe0, 0x10b)
    struct.pack_into('<HH', data, 0x84, machine, 2)
    struct.pack_into('<H', data, 0x94, size)
    opt = 0x98
    struct.pack_into('<H', data, opt, magic)
    base = 0x140000000 if bits == 64 else 0x400000
    struct.pack_into('<Q' if bits == 64 else '<I', data, opt + (24 if bits == 64 else 28), base)
    struct.pack_into('<I', data, opt + 56, 0x3000)
    struct.pack_into('<I', data, opt + (108 if bits == 64 else 92), 16)
    directory = opt + (112 if bits == 64 else 96)
    struct.pack_into('<II', data, directory + 5 * 8, 0x2000, 12)
    struct.pack_into('<II', data, directory + 12 * 8, 0x1020, 8)
    for i, (name, rva, raw, flags) in enumerate([(b'.text', 0x1000, 0x200, 0x60000020),
                                                (b'.reloc', 0x2000, 0x400, 0x42000040)]):
        at = opt + size + i * 40
        data[at:at + len(name)] = name
        struct.pack_into('<IIII', data, at + 8, 0x200, rva, 0x200, raw)
        struct.pack_into('<I', data, at + 36, flags)
    struct.pack_into('<Q' if bits == 64 else '<I', data, 0x210, base + 0x1234)
    struct.pack_into('<IIHH', data, 0x400, 0x1000, 12, (10 if bits == 64 else 3) << 12 | 0x10, 0)
    return data, base


@pytest.mark.parametrize('bits', [32, 64])
def test_relocation_aware_code_comparison(bits):
    data, base = pe_fixture(bits)
    pe = PE(bytes(data))
    section, expected = list(pe.expected_code(base + 0x10000))[0]
    width = bits // 8
    assert int.from_bytes(expected[0x10:0x10 + width], 'little') == base + 0x1234 + 0x10000
    actual = bytearray(expected)
    actual[0x20:0x28] = b'\xff' * 8  # Loader-managed IAT must not be a false alarm.
    assert code_difference(expected, actual, section.rva, pe.directory(12))[1] == 0
    actual[0x35] ^= 0xff
    compared, changed, offsets = code_difference(expected, actual, section.rva, pe.directory(12))
    assert changed == 1 and offsets == ['0x1035'] and compared == len(expected) - 8


@pytest.mark.parametrize('data', [b'', b'MZ', b'MZ' + bytes(512), bytes(4096)])
def test_bad_pe_rejected(data):
    with pytest.raises((ValueError, struct.error)):
        PE(data)


def test_relocation_and_scan_limits():
    data, base = pe_fixture()
    pe = PE(bytes(data))
    assert len(list(pe.expected_code(base, limit=32))[0][1]) == 32
    struct.pack_into('<I', data, 0x404, 0xfffffff0)
    with pytest.raises(ValueError, match='Malformed'):
        PE(bytes(data)).relocations()
    data, _ = pe_fixture()
    struct.pack_into('<H', data, 0x408, 9 << 12 | 0x10)
    with pytest.raises(ValueError, match='Unsupported relocation'):
        PE(bytes(data)).relocations()


def test_priority_unknown_is_not_unsigned():
    assert priority(row(), None)[0] == 0
    assert priority(row(), Signature('каталожная проверка недоступна'))[0] == 0
    assert priority(row(), Signature('подпись не найдена'))[0] == 20
    assert priority(row(), Signature('Microsoft: доверена'))[0] == 0
    assert priority(row(), evidence={'public_ip': True})[0] == 0


def test_priority_explainable_capped_and_temp_boundary():
    candidate = row(exe=r'C:\Windows\Temp\svchost.exe', cpu=80, findings='нетипичный путь системного имени')
    score, notes = priority(candidate, Signature('подпись не найдена'),
                            {'memory_difference': True, 'thread_outside': True, 'sensitive_token': True})
    assert score == 100 and '+40: EXE в Temp' in notes and 'легитимные hooks' in notes
    assert priority(row(exe=r'C:\Windows\Temp_not\app.exe'))[0] == 0


def test_snapshot_pid_restart_ignored_but_new_exe_reported():
    baseline = {'processes': [asdict(row())]}
    current = {'processes': [asdict(row(pid=200, created=999, cpu=90))]}
    assert snapshots.compare(baseline, current) == []
    current['processes'].append(asdict(row(pid=201, exe=r'C:\Other\new.exe', name='new.exe')))
    diff = snapshots.compare(baseline, current)
    assert len(diff) == 1 and diff[0]['Изменение'] == 'Добавлено'
    assert snapshots.process_key(row(exe=r'C:\APPS\EXAMPLE.exe')) == snapshots.process_key(row())


def test_snapshot_config_diff_not_service_runtime_status():
    baseline = {'services': [{'name': 'test', 'binpath': 'a', 'status': 'stopped'}]}
    current = {'services': [{'name': 'test', 'binpath': 'a', 'status': 'running'}]}
    assert snapshots.compare(baseline, current) == []
    current['services'][0]['binpath'] = 'b'
    assert snapshots.compare(baseline, current)[0]['Изменение'] == 'Изменено'


def test_snapshot_missing_coverage_is_not_false_removal():
    baseline = {'services': [{'name': 'service'}], 'coverage': {'services': True}}
    current = {'services': [], 'coverage': {'services': False}}
    result = snapshots.compare(baseline, current)
    assert len(result) == 1 and result[0]['Изменение'] == 'Не сравнивалось'


def test_snapshot_json_validation_and_roundtrip(tmp_path):
    path = tmp_path / 'снимок.json'
    value = {'schema': 1, 'processes': [asdict(row())]}
    snapshots.atomic_json(path, value)
    assert snapshots.load(path) == value
    path.write_text('{"schema":1,"processes":[{"exe":[]}]}')
    with pytest.raises(ValueError, match='поля'):
        snapshots.load(path)
    path.write_text('{"schema":900}')
    with pytest.raises(ValueError, match='схема'):
        snapshots.load(path)


def test_capture_partial_errors_are_explicit(monkeypatch, tmp_path):
    def failure(*_):
        raise PermissionError('no access')
    monkeypatch.setattr(snapshots, 'list_services', failure)
    monkeypatch.setattr(snapshots, 'WinRegistry', failure)
    value = snapshots.capture([row()], tmp_path)
    assert len(value['errors']) == 2 and value['coverage']['tasks'] is False
    assert value['coverage']['services'] is False
    assert not (tmp_path / 'startup-backup.json').exists()


def test_quarantine_is_verified_container_not_renamed_pe(tmp_path):
    source, container = tmp_path / 'app.exe', tmp_path / 'app.vir'
    content = b'MZ' + bytes(range(256)) * 10
    source.write_bytes(content)
    metadata = quarantine.pack_file(source, container)
    assert source.read_bytes() == content  # Packing alone never stops/deletes a process.
    assert container.read_bytes()[:2] == b'PK'
    with zipfile.ZipFile(container) as archive:
        assert archive.testzip() is None and set(archive.namelist()) == {'sample.bin', 'metadata.json'}
        assert archive.read('sample.bin') == content
        assert json.loads(archive.read('metadata.json'))['sha256'] == hashlib.sha256(content).hexdigest()
    assert metadata['size'] == len(content)


def test_quarantine_changing_source_does_not_commit(tmp_path, monkeypatch):
    source, container = tmp_path / 'a.exe', tmp_path / 'a.vir'
    source.write_bytes(b'MZfixture')
    calls = []
    def changing_hash(path):
        calls.append(path)
        return 'a' if len(calls) == 1 else 'b'
    monkeypatch.setattr(quarantine, 'hash_file', changing_hash)
    with pytest.raises(OperationError, match='изменился'):
        quarantine.pack_file(source, container)
    assert not container.exists() and source.exists()
    assert not container.with_suffix('.tmp').exists()


def test_quarantine_no_stop_before_verified_pack(monkeypatch, tmp_path):
    source = tmp_path / 'test.exe'
    source.write_bytes(b'MZfixture')
    stopped = []
    process = SimpleNamespace(exe=lambda: str(source), terminate=lambda: stopped.append(True), wait=lambda **kw: None)
    monkeypatch.setattr(quarantine, 'checked_process', lambda *a, **kw: process)
    monkeypatch.setattr(quarantine, 'safe_delete_path', lambda _: source)
    def failed_pack(*args):
        raise OperationError('verification failed')
    monkeypatch.setattr(quarantine, 'pack_file', failed_pack)
    with pytest.raises(OperationError, match='verification failed'):
        quarantine.quarantine_process(123, 456, tmp_path)
    assert not stopped and source.exists()


def test_quarantine_termination_failure_retains_container_and_source(monkeypatch, tmp_path):
    source = tmp_path / 'test.exe'
    source.write_bytes(b'MZfixture')
    def denied():
        raise PermissionError('no terminate')
    process = SimpleNamespace(exe=lambda: str(source), terminate=denied)
    monkeypatch.setattr(quarantine, 'checked_process', lambda *a, **kw: process)
    monkeypatch.setattr(quarantine, 'safe_delete_path', lambda _: source)
    with pytest.raises(OperationError, match='сохранена'):
        quarantine.quarantine_process(123, 456, tmp_path)
    assert source.exists() and len(list((tmp_path / 'quarantine').glob('*.vir'))) == 1


def test_system_watch_diffs_not_attribution():
    before = {'hosts': {'sha256': 'a'}, 'dns': {}, 'ifeo': []}
    assert system_watch.changes(None, before) == []
    assert system_watch.changes(before, dict(before)) == []
    after = {**before, 'hosts': {'sha256': 'b'}, 'ifeo': [{'image': 'cmd.exe', 'Debugger': 'legit.exe'}]}
    result = system_watch.changes(before, after)
    assert {r['Область'] for r in result} == {'hosts', 'ifeo'}
    assert all('не установлен' in r['Примечание'] for r in result)
    assert system_watch.registry_value(b'\xff') == {'binary_hex': 'ff', 'size': 1}


def test_audit_xml_parse_is_data_not_code():
    xml = '''<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
    <System><EventID>1</EventID><EventRecordID>99</EventRecordID><TimeCreated SystemTime="2026-10-28T11:00:00Z"/></System>
    <EventData><Data Name="Image">C:\\Windows\\vssadmin.exe</Data>
    <Data Name="CommandLine">vssadmin delete shadows /all</Data></EventData></Event>'''
    result = event_audit.parse_event(xml, event_audit.SYSMON)
    assert result['ID'] == 1 and result['Record'] == '99' and 'ручной проверки' in result['Замечание']
    assert 'vssadmin' in result['Данные']


def test_memory_timeout_is_not_clean(monkeypatch):
    from opentask import forensics
    monkeypatch.setattr(forensics, 'require_windows', lambda: None)
    monkeypatch.setattr(forensics, 'checked_process', lambda *_: None)
    monkeypatch.setattr(forensics.subprocess, 'CREATE_NO_WINDOW', 0, raising=False)
    def timeout(*args, **kwargs):
        raise forensics.subprocess.TimeoutExpired('probe', 15)
    monkeypatch.setattr(forensics.subprocess, 'run', timeout)
    with pytest.raises(OperationError, match='не «чисто»'):
        forensics.memory_report(123, 456)
