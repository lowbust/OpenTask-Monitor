"""Build the public one-EXE release ZIP; no Windows compiler VM is required.

Dependencies are compressed into a PE resource. Native first-start extraction
uses vendored MIT miniz, no PowerShell/shell/network, then caches the runtime.
The ZIP presented to end users contains exactly OpenTaskMonitor.exe.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import tomllib
import zipfile
from pathlib import Path

from build_embedded_portable import ROOT, build

VERSION = '0.3.0'


def payload_names(package: Path):
    for path in sorted(package.rglob('*')):
        relative = path.relative_to(package)
        if (path.is_file() and path.suffix != '.pyc' and '__pycache__' not in relative.parts
                and relative.name != '.ready' and not (len(relative.parts) == 1 and path.suffix == '.exe')):
            yield path, relative


def compile_single(work: Path, output: Path, gcc: str, windres: str):
    project_version = tomllib.loads((ROOT / 'pyproject.toml').read_text())['project']['version']
    if project_version != VERSION:
        raise RuntimeError('Single-file builder VERSION differs from pyproject.toml')
    work = work.resolve()
    work.mkdir(parents=True, exist_ok=True)
    build(work, work / 'unused.zip', gcc, windres, pack=False)
    package = work / 'package' / 'OpenTaskMonitor'
    info = json.loads((package / 'BUILD-INFO.json').read_text(encoding='utf-8'))
    info['source_references']['miniz'] = 'https://github.com/richgel999/miniz/tree/3.0.2'
    info.update({'format': 'single-exe with offline per-user runtime cache',
                 'cache': '%LOCALAPPDATA%/OpenTaskMonitor/packages/<version-payload-hash>',
                 'extractor': 'miniz 3.0.2 (MIT), reader/inflate only', 'runtime_network_downloads': False})
    (package / 'BUILD-INFO.json').write_text(json.dumps(info, indent=2), encoding='utf-8')
    payload = work / 'payload.zip'
    with zipfile.ZipFile(payload, 'w', zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
        for path, relative in payload_names(package):
            archive.write(path, relative)
    with zipfile.ZipFile(payload) as archive:
        if archive.testzip() is not None:
            raise RuntimeError('Payload ZIP integrity failed')
    digest = hashlib.sha256(payload.read_bytes()).hexdigest()
    header = work / 'payload_info.h'
    header.write_text(f'#pragma once\n#define OTM_PAYLOAD_HASH "{digest}"\n'
                      f'#define OTM_PAYLOAD_ID L"{VERSION}-{digest[:16]}"\n', encoding='ascii')
    resources = work / 'singlefile.rc'
    # Paths in RC strings use forward slashes, on Windows as well as under MinGW/Linux.
    resources.write_text(f'#include "{(ROOT / "native/launcher.rc").as_posix()}"\n'
                         f'202 RCDATA "{payload.as_posix()}"\n', encoding='utf-8')
    obj = work / 'singlefile-res.o'
    subprocess.run([windres, '-I', str(ROOT / 'native'), str(resources), '-o', str(obj)],
                   cwd=ROOT, check=True)
    executable = work / 'OpenTaskMonitor.exe'
    vendor = ROOT / 'third_party/miniz'
    subprocess.run([
        gcc, '-Os', '-s', '-static', '-municode', '-mwindows', '-Wall', '-Wextra',
        '-finput-charset=UTF-8', '-DOPENTASK_SINGLEFILE', '-DMINIZ_NO_STDIO', '-DMINIZ_NO_TIME',
        '-DMINIZ_NO_DEFLATE_APIS', '-DMINIZ_NO_ZLIB_APIS',
        '-I', str(vendor), '-I', str(work), '-I', str(ROOT / 'native'),
        str(ROOT / 'native/launcher.c'), str(ROOT / 'native/singlefile.c'),
        str(vendor / 'miniz.c'), str(vendor / 'miniz_zip.c'), str(vendor / 'miniz_tinfl.c'),
        str(obj), '-o', str(executable), '-lbcrypt', '-lgdi32',
    ], check=True)
    output = output.resolve()
    output.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(output, 'w', zipfile.ZIP_DEFLATED, compresslevel=6) as archive:
        archive.write(executable, 'OpenTaskMonitor.exe')
    with zipfile.ZipFile(output) as archive:
        if archive.namelist() != ['OpenTaskMonitor.exe'] or archive.testzip() is not None:
            raise RuntimeError('Public ZIP must contain exactly one valid EXE')
    print(f'Single-file EXE: {executable} ({executable.stat().st_size:,} bytes)')
    print(f'Ready: {output} ({output.stat().st_size:,} bytes)')
    print(f'Payload cache ID: {VERSION}-{digest[:16]}')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--work', type=Path, default=ROOT / 'build/embedded')
    parser.add_argument('--output', type=Path,
                        default=ROOT / f'release/OpenTaskMonitor-{VERSION}-windows-x64-portable.zip')
    parser.add_argument('--gcc', default='x86_64-w64-mingw32-gcc')
    parser.add_argument('--windres', default='x86_64-w64-mingw32-windres')
    options = parser.parse_args()
    compile_single(options.work, options.output, options.gcc, options.windres)
