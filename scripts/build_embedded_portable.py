"""Build a self-contained Windows x64 ZIP, including the unmodified CPython runtime.

Can run on Linux with MinGW-w64, or Windows with a MinGW-w64 toolchain on PATH.
Downloads are build-time only, pinned by SHA-256. No downloads at application runtime.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import subprocess
import sys
import urllib.request
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PYTHON_FILE = 'python-3.12.10-embed-amd64.zip'
PYTHON_URL = f'https://www.python.org/ftp/python/3.12.10/{PYTHON_FILE}'
HASHES = {
    PYTHON_FILE: '4acbed6dd1c744b0376e3b1cf57ce906f9dc9e95e68824584c8099a63025a3c3',
    'PySide6_Essentials-6.8.3-cp39-abi3-win_amd64.whl':
        '3c0fae5550aff69f2166f46476c36e0ef56ce73d84829eac4559770b0c034b07',
    'psutil-7.2.2-cp37-abi3-win_amd64.whl':
        'eb7e81434c8d223ec4a219b5fc1c47d0417b12be7ea866e24fb5ad6e84b3d988',
    'shiboken6-6.8.3-cp39-abi3-win_amd64.whl':
        'bca3a94513ce9242f7d4bbdca902072a1631888e0aa3a8711a52cc5dbe93588f',
}


def verify(path: Path):
    expected = HASHES.get(path.name)
    actual = hashlib.sha256(path.read_bytes()).hexdigest()
    if not expected or expected != actual:
        raise RuntimeError(f'SHA-256 mismatch: {path.name}')


def build(work: Path, output: Path, gcc: str, windres: str, pack: bool = True):
    downloads = work / 'downloads'
    downloads.mkdir(parents=True, exist_ok=True)
    python_zip = downloads / PYTHON_FILE
    if not python_zip.exists():
        with urllib.request.urlopen(PYTHON_URL, timeout=90) as response:
            python_zip.write_bytes(response.read())
    verify(python_zip)
    if not all((downloads / name).exists() for name in HASHES):
        subprocess.run([
            sys.executable, '-m', 'pip', 'download', '--dest', str(downloads), '--only-binary=:all:',
            '--platform', 'win_amd64', '--python-version', '312', '--implementation', 'cp',
            '--abi', 'cp312', '--abi', 'abi3', 'PySide6-Essentials==6.8.3', 'psutil==7.2.2',
        ], check=True)
    package = work / 'package' / 'OpenTaskMonitor'
    if package.exists():
        shutil.rmtree(package)
    runtime = package / 'runtime'
    runtime.mkdir(parents=True)
    with zipfile.ZipFile(python_zip) as archive:
        archive.extractall(runtime)
    site = runtime / 'Lib' / 'site-packages'
    site.mkdir(parents=True)
    for filename in HASHES:
        if filename.endswith('.whl'):
            wheel = downloads / filename
            verify(wheel)
            with zipfile.ZipFile(wheel) as archive:
                archive.extractall(site)
    (runtime / 'python312._pth').write_text('python312.zip\n.\nLib\\site-packages\nimport site\n',
                                           encoding='utf-8')
    shutil.copytree(ROOT / 'src' / 'opentask', site / 'opentask',
                    ignore=shutil.ignore_patterns('__pycache__', '*.pyc'))
    shutil.copy2(ROOT / 'scripts' / 'bootstrap.py', runtime / 'bootstrap.py')
    resource = work / 'launcher-res.o'
    subprocess.run([windres, '-I', str(ROOT / 'native'), str(ROOT / 'native' / 'launcher.rc'),
                    '-o', str(resource)], cwd=ROOT, check=True)
    subprocess.run([gcc, '-Os', '-s', '-static', '-municode', '-mwindows', '-Wall', '-Wextra',
                    '-finput-charset=UTF-8', str(ROOT / 'native' / 'launcher.c'), str(resource),
                    '-o', str(package / 'OpenTaskMonitor.exe'), '-lbcrypt'], check=True)
    for name in ('LICENSE', 'THIRD_PARTY_NOTICES.md', 'SECURITY.md', 'VERIFICATION.md'):
        shutil.copy2(ROOT / name, package / name)
    shutil.copytree(ROOT / 'third_party', package / 'third_party')
    shutil.copytree(ROOT / 'docs', package / 'docs')
    shutil.copy2(ROOT / 'docs' / 'PORTABLE-START.txt', package / 'START-HERE.txt')
    shutil.copy2(runtime / 'LICENSE.txt', package / 'third_party' / 'Python-LICENSE.txt')
    manifest = {
        'app_version': '0.3.0', 'target': 'Windows 10/11 x64', 'python': '3.12.10',
        'PySide6-Essentials': '6.8.3', 'shiboken6': '6.8.3', 'psutil': '7.2.2',
        'input_sha256': HASHES,
        'source_references': {
            'python': 'https://www.python.org/ftp/python/3.12.10/Python-3.12.10.tar.xz',
            'pyside_shiboken': 'https://code.qt.io/cgit/pyside/pyside-setup.git/?h=v6.8.3',
            'qt': 'https://code.qt.io/cgit/qt/qtbase.git/?h=v6.8.3',
            'qt_supermodule': 'https://code.qt.io/cgit/qt/qt5.git/?h=v6.8.3',
            'psutil': 'https://github.com/giampaolo/psutil/tree/release-7.2.2',
        },
        'upstream_binaries_modified': False,
    }
    (package / 'BUILD-INFO.json').write_text(json.dumps(manifest, indent=2), encoding='utf-8')
    if not pack:
        print(f'Unpacked application: {package}')
        return
    output.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(output, 'w', zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
        for path in sorted(package.rglob('*')):
            if path.is_file() and '__pycache__' not in path.parts and path.suffix != '.pyc':
                archive.write(path, path.relative_to(package.parent))
    with zipfile.ZipFile(output) as archive:
        if archive.testzip() is not None:
            raise RuntimeError('Output ZIP integrity check failed')
    print(f'Ready: {output} ({output.stat().st_size:,} bytes)')
    print(f'Unpacked application: {package}')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--work', type=Path, default=ROOT / 'build' / 'embedded')
    parser.add_argument('--output', type=Path,
                        default=ROOT / 'release' / 'OpenTaskMonitor-0.3.0-windows-x64-portable.zip')
    parser.add_argument('--unpacked-only', action='store_true')
    parser.add_argument('--gcc', default='x86_64-w64-mingw32-gcc')
    parser.add_argument('--windres', default='x86_64-w64-mingw32-windres')
    args = parser.parse_args()
    build(args.work.resolve(), args.output.resolve(), args.gcc, args.windres, not args.unpacked_only)
