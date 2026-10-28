import hashlib
import json
from dataclasses import replace
from types import SimpleNamespace

import pytest

from opentask import inspection
from opentask.backend import OperationError
from opentask.core import ProcessRow
from opentask.ui.inspector import tree_relationships


def process(pid, parent, name, created=100):
    return ProcessRow(pid, parent, name, 'user', 0, 0, 1, 'running', created)


@pytest.mark.parametrize(('name', 'path', 'alert'), [
    ('svchost.exe', r'C:\Windows\System32\svchost.exe', False),
    ('SVCHOST.EXE', r'C:\WINDOWS\SysWOW64\svchost.exe', False),
    ('svchost.exe', r'C:\Users\User\AppData\svchost.exe', True),
    ('svchost.exe', r'C:\Windows\System32_bad\svchost.exe', True),
    ('lsass.exe', r'C:\Temp\lsass.exe', True),
    ('explorer.exe', r'C:\Windows\explorer.exe', False),
    ('explorer.exe', r'C:\Temp\explorer.exe', True),
    ('myapp.exe', r'C:\Temp\myapp.exe', False),
    ('svchost.exe', '', False),
])
def test_path_hints(name, path, alert):
    assert bool(inspection.path_findings(name, path)) == alert


def test_parent_hint_and_pid_reuse():
    child = process(10, 5, 'powershell.exe', 200)
    assert inspection.parent_findings(child, {5: process(5, 1, 'unknown.exe')})
    assert not inspection.parent_findings(child, {5: process(5, 1, 'explorer.exe')})
    assert not inspection.parent_findings(child, {5: process(5, 1, 'unknown.exe', 300)})
    assert not inspection.parent_findings(child, {})


def test_tree_rejects_reused_parent():
    parent = process(1, 0, 'old.exe', 300)
    child = process(2, 1, 'cmd.exe', 200)
    assert tree_relationships([parent, child]) == {1: None, 2: None}
    assert tree_relationships([replace(parent, created=100), child])[2] == 1


def test_hash_file(tmp_path):
    path = tmp_path / 'test.bin'
    path.write_bytes(b'hello world')
    assert inspection.hash_file(str(path)) == hashlib.sha256(b'hello world').hexdigest()


def test_virustotal_only_sends_hash(tmp_path, monkeypatch):
    path = tmp_path / 'secret-name.exe'
    path.write_bytes(b'example')
    requests = []
    class Response:
        def __enter__(self):
            return self
        def __exit__(self, *args):
            pass
        def read(self, limit):
            return json.dumps({'data': {'attributes': {'last_analysis_stats': {'malicious': 1}}}}).encode()
    def opened(request, timeout):
        requests.append(request)
        return Response()
    monkeypatch.setattr(inspection.urllib.request, 'build_opener',
                        lambda *_: SimpleNamespace(open=opened))
    result = inspection.virustotal(str(path), 'a' * 64)
    request = requests[0]
    assert request.full_url.endswith(hashlib.sha256(b'example').hexdigest())
    assert request.get_method() == 'GET'
    assert request.data is None
    assert path.name not in request.full_url
    assert 'a' * 64 not in str(result)
    assert result['Статистика']['malicious'] == 1


def test_virustotal_rate_limit(monkeypatch):
    monkeypatch.setattr(inspection.time, 'monotonic', lambda: 100)
    limiter = inspection.RateLimit()
    limiter.acquire()
    with pytest.raises(OperationError, match='16'):
        limiter.acquire()
    monkeypatch.setattr(inspection.time, 'monotonic', lambda: 117)
    limiter.acquire()


def test_disconnect_ipv6_rejected_without_mutation(monkeypatch):
    monkeypatch.setattr(inspection, 'require_windows', lambda: None)
    monkeypatch.setattr(inspection, 'checked_process', lambda *a, **kw: SimpleNamespace(pid=123))
    with pytest.raises(OperationError, match='IPv4'):
        inspection.disconnect(123, 100, {'Протокол': 'TCP', 'Семейство': 'IPv6', 'Удалённый IP': '::1'})


def test_kill_tree_preflight_no_partial_kill(monkeypatch):
    killed = []
    child = SimpleNamespace(pid=2, create_time=lambda: 100)
    root = SimpleNamespace(children=lambda recursive: [child], terminate=lambda: killed.append(1))
    def checked(pid, created, mutation):
        if pid == 2:
            raise OperationError('critical')
        return root
    monkeypatch.setattr(inspection, 'checked_process', checked)
    monkeypatch.setattr(inspection.psutil, 'Process', lambda: SimpleNamespace(parents=lambda: []))
    with pytest.raises(OperationError):
        inspection.kill_tree(1, 100)
    assert killed == []


def test_invalid_api_key_not_echoed(tmp_path):
    secret = 'private-key\nmalformed'
    with pytest.raises(OperationError) as exc:
        inspection.virustotal(str(tmp_path / 'missing.exe'), secret)
    assert secret not in str(exc.value)


def test_delete_blocks_original_singlefile_launcher(tmp_path, monkeypatch):
    launcher = tmp_path / 'OpenTaskMonitor.exe'
    launcher.write_bytes(b'test-only-not-an-executable')
    monkeypatch.setenv('OPENTASK_LAUNCHER', str(launcher))
    monkeypatch.setattr(inspection, 'require_windows', lambda: None)
    with pytest.raises(OperationError, match='запускающего EXE'):
        inspection.safe_delete_path(str(launcher))
    assert launcher.exists()
