import json
from dataclasses import replace

import pytest

from opentask.backend import OperationError
from opentask.startup import BackupStore, StartupEntry, StartupManager, entry_id


class FakeRegistry:
    def __init__(self):
        self.values = {('HKCU', 'TestApp'): (r'%SystemRoot%\example.exe --test', 2)}
        self.fail_delete = False
        self.fail_set = False

    def list(self, location):
        return [(name, data, kind) for (loc, name), (data, kind) in self.values.items() if loc == location]

    def get(self, location, name):
        return self.values.get((location, name))

    def delete(self, location, name):
        if self.fail_delete:
            raise PermissionError('fake denied')
        del self.values[(location, name)]

    def set(self, location, name, command, kind):
        if self.fail_set:
            raise PermissionError('fake denied')
        self.values[(location, name)] = (command, kind)


@pytest.fixture
def setup(tmp_path):
    registry = FakeRegistry()
    store = BackupStore(tmp_path / 'startup-backup.json')
    return registry, store, StartupManager(registry, store)


def test_disable_restore_roundtrip(setup):
    registry, store, manager = setup
    entry = manager.entries()[0]
    manager.toggle(entry)
    assert registry.get('HKCU', 'TestApp') is None
    disabled = manager.entries()[0]
    assert not disabled.enabled
    assert store.path.exists()
    manager.toggle(disabled)
    assert registry.get('HKCU', 'TestApp') == (entry.command, 2)
    assert store.load() == {}


def test_backup_survives_restart(setup):
    registry, store, manager = setup
    manager.toggle(manager.entries()[0])
    new_manager = StartupManager(registry, BackupStore(store.path))
    assert not new_manager.entries()[0].enabled
    new_manager.toggle(new_manager.entries()[0])
    assert registry.get('HKCU', 'TestApp') is not None


def test_preserve_original_if_backup_write_fails(setup, monkeypatch):
    registry, store, manager = setup
    def fail(entries):
        raise OSError('disk full')
    monkeypatch.setattr(store, 'save', fail)
    with pytest.raises(OSError):
        manager.toggle(manager.entries()[0])
    assert registry.get('HKCU', 'TestApp') is not None


def test_copy_remains_if_registry_delete_fails(setup):
    registry, store, manager = setup
    registry.fail_delete = True
    with pytest.raises(PermissionError):
        manager.toggle(manager.entries()[0])
    assert len(store.load()) == 1
    assert registry.get('HKCU', 'TestApp') is not None
    # A crash/failure can leave BOTH entries. Enable copy to safely reconcile.
    registry.fail_delete = False
    disabled = next(e for e in manager.entries() if not e.enabled)
    manager.toggle(disabled)
    assert store.load() == {}
    assert len(manager.entries()) == 1


def test_conflict_not_overwritten(setup):
    registry, store, manager = setup
    manager.toggle(manager.entries()[0])
    disabled = next(iter(store.load().values()))
    registry.set('HKCU', 'TestApp', 'different.exe', 1)
    with pytest.raises(OperationError, match='Перезапись'):
        manager.toggle(disabled)
    assert registry.get('HKCU', 'TestApp') == ('different.exe', 1)
    assert store.load()


def test_stale_entry_not_deleted(setup):
    registry, store, manager = setup
    entry = manager.entries()[0]
    registry.set('HKCU', 'TestApp', 'changed.exe', 1)
    with pytest.raises(OperationError, match='изменилась'):
        manager.toggle(entry)
    assert store.load() == {}


def test_restore_failure_keeps_backup(setup):
    registry, store, manager = setup
    manager.toggle(manager.entries()[0])
    registry.fail_set = True
    with pytest.raises(PermissionError):
        manager.toggle(manager.entries()[0])
    assert store.load()


def test_invalid_location_blocked(setup):
    _, _, manager = setup
    entry = StartupEntry(entry_id('BAD', 'X'), 'X', 'x.exe', 'BAD', 1, True)
    with pytest.raises(OperationError):
        manager.toggle(entry)


def test_readonly_entry_blocked(setup):
    _, _, manager = setup
    with pytest.raises(OperationError):
        manager.toggle(replace(manager.entries()[0], editable=False))


def test_backup_corrupt_blocked(setup):
    registry, store, manager = setup
    store.path.write_text('{broken', encoding='utf-8')
    with pytest.raises(OperationError, match='Повреждена'):
        manager.entries()
    assert registry.get('HKCU', 'TestApp') is not None


def test_backup_injected_location_blocked(setup):
    _, store, manager = setup
    manager.toggle(manager.entries()[0])
    payload = json.loads(store.path.read_text(encoding='utf-8'))
    payload['entries'][0]['location'] = 'RunOnce'
    store.path.write_text(json.dumps(payload), encoding='utf-8')
    with pytest.raises(OperationError):
        store.load()


def test_id_case_insensitive():
    assert entry_id('HKCU', 'Example') == entry_id('HKCU', 'EXAMPLE')
    assert entry_id('HKCU', 'X') != entry_id('HKLM64', 'X')
