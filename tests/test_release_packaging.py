import importlib.util
from pathlib import Path


def load_script(name):
    path = Path(__file__).resolve().parents[1] / 'scripts' / (name + '.py')
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_source_archive_excludes_build_and_executables():
    include = load_script('build_source_release').include_source
    assert include(Path('src/opentask/launch_mode.py'))
    assert include(Path('.github/workflows/build-windows.yml'))
    assert include(Path('third_party/miniz/miniz.c'))
    assert include(Path('assets/opentask.ico'))
    for path in ['build/embedded/payload.zip', 'runtime/pythonw.exe', 'app.dll',
                 '.venv/a.py', 'src/opentask/__pycache__/a.pyc', 'release/app.zip',
                 'distribution.egg-info/PKG-INFO', 'runtime/Lib/private.py', '.env']:
        assert not include(Path(path))


def test_singlefile_payload_does_not_contain_entry_exe(tmp_path, monkeypatch):
    monkeypatch.syspath_prepend(str(Path(__file__).resolve().parents[1] / 'scripts'))
    module = load_script('build_singlefile')
    for path in ['OpenTaskMonitor.exe', 'runtime/pythonw.exe', 'runtime/bootstrap.py',
                 'runtime/__pycache__/x.pyc', '.ready', 'LICENSE']:
        target = tmp_path / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text('test')
    names = [relative.as_posix() for _, relative in module.payload_names(tmp_path)]
    assert set(names) == {'runtime/pythonw.exe', 'runtime/bootstrap.py', 'LICENSE'}
    assert module.VERSION == '0.2.2'
