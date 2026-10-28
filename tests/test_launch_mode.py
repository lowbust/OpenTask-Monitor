from pathlib import Path

from opentask.launch_mode import random_enabled, set_random_enabled


def test_missing_preference_defaults_to_normal(tmp_path):
    assert not random_enabled(tmp_path)


def test_roundtrip_exact_native_ini_format(tmp_path):
    set_random_enabled(tmp_path, True)
    assert random_enabled(tmp_path)
    assert (tmp_path / 'launch.ini').read_bytes() == b'[Launch]\r\nRandomName=1\r\n'
    set_random_enabled(tmp_path, False)
    assert not random_enabled(tmp_path)
    assert (tmp_path / 'launch.ini').read_bytes() == b'[Launch]\r\nRandomName=0\r\n'
    assert not list(tmp_path.glob('launch-*.tmp'))


def test_bad_preferences_default_to_normal(tmp_path):
    for value in [b'broken', b'[Launch]\nRandomName=2\n', b'\xff\xff']:
        (tmp_path / 'launch.ini').write_bytes(value)
        assert not random_enabled(tmp_path)


def test_creates_data_folder(tmp_path):
    folder = tmp_path / 'new' / 'nested'
    set_random_enabled(folder, True)
    assert random_enabled(folder)


def test_permission_failure_does_not_destroy_old_preference(tmp_path, monkeypatch):
    import os

    import pytest
    set_random_enabled(tmp_path, True)
    def failure(source: Path, dest: Path):
        raise PermissionError('test-only')
    monkeypatch.setattr(os, 'replace', failure)
    with pytest.raises(PermissionError):
        set_random_enabled(tmp_path, False)
    assert random_enabled(tmp_path)
    assert not list(tmp_path.glob('launch-*.tmp'))
