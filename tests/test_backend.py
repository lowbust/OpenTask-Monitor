import os
from types import SimpleNamespace

import psutil
import pytest

from opentask import backend


def fake_process(name='notepad.exe', created=123):
    return SimpleNamespace(create_time=lambda: created, name=lambda: name)


def test_checked_process_rejects_reused_pid(monkeypatch):
    monkeypatch.setattr(backend.psutil, 'Process', lambda pid: fake_process(created=999))
    with pytest.raises(backend.OperationError, match='PID'):
        backend.checked_process(9876, 123)


def test_checked_process_accepts_matching_identity(monkeypatch):
    process = fake_process()
    monkeypatch.setattr(backend.psutil, 'Process', lambda pid: process)
    assert backend.checked_process(9876, 123) is process


@pytest.mark.parametrize('pid', [0, 4, os.getpid()])
def test_dangerous_pid_blocked(pid):
    with pytest.raises(backend.OperationError):
        backend.checked_process(pid, 1, mutation=True)


def test_critical_name_blocked(monkeypatch):
    monkeypatch.setattr(backend.psutil, 'Process', lambda pid: fake_process(name='LSASS.EXE'))
    with pytest.raises(backend.OperationError, match='критического'):
        backend.checked_process(9876, 123, mutation=True)


def test_process_disappeared(monkeypatch):
    def missing(pid):
        raise psutil.NoSuchProcess(pid)
    monkeypatch.setattr(backend.psutil, 'Process', missing)
    with pytest.raises(psutil.NoSuchProcess):
        backend.checked_process(9876, 123)


def test_collector_readonly_smoke():
    collector = backend.Collector()
    first = collector.collect()
    second = collector.collect()
    assert 0 <= first.cpu <= 100
    assert first.memory_total > 0
    assert len(second.processes) > 0
    assert all(p.cpu >= 0 and p.memory >= 0 for p in second.processes)
    assert first.net_recv == 0 and first.disk_read == 0


def test_collector_metadata_cached(monkeypatch):
    from contextlib import nullcontext
    counts = {'user': 0, 'name': 0}
    def username():
        counts['user'] += 1
        return 'user'
    def name():
        counts['name'] += 1
        return 'test.exe'
    fake = SimpleNamespace(pid=999, oneshot=nullcontext, create_time=lambda: 100,
                           ppid=lambda: 1, name=name, username=username, num_threads=lambda: 2,
                           status=lambda: 'running', exe=lambda: 'test.exe', cpu_percent=lambda **kw: 10,
                           memory_info=lambda: SimpleNamespace(rss=1024))
    monkeypatch.setattr(backend.psutil, 'process_iter', lambda: iter([fake]))
    collector = backend.Collector()
    collector.collect()
    collector.collect()
    assert counts == {'user': 1, 'name': 1}
