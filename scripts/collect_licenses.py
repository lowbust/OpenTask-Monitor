"""Collect installed notices and exact version/source references for portable builds.

This is packaging help, not a substitute for a release-specific license audit.
"""
from __future__ import annotations

import importlib.metadata as metadata
import json
import shutil
import sys
from pathlib import Path

from PySide6.QtCore import qVersion

PACKAGES = ('PySide6-Essentials', 'shiboken6', 'psutil', 'pyinstaller')


def collect(destination: Path):
    project = Path(__file__).resolve().parents[1]
    licenses = destination / 'third_party'
    shutil.copytree(project / 'third_party', licenses, dirs_exist_ok=True)
    for filename in ('LICENSE.txt', 'LICENSE'):
        python_license = Path(sys.base_prefix) / filename
        if python_license.is_file():
            shutil.copy2(python_license, licenses / 'Python-LICENSE.txt')
            break
    manifest = {'python': sys.version, 'qt': qVersion(), 'packages': {}}
    for name in PACKAGES:
        dist = metadata.distribution(name)
        manifest['packages'][name] = {
            'version': dist.version,
            'license': dist.metadata.get('License-Expression') or dist.metadata.get('License', ''),
            'project_urls': dist.metadata.get_all('Project-URL') or [],
            'homepage': dist.metadata.get('Home-page', ''),
        }
        for file in dist.files or []:
            if any(token in str(file).casefold() for token in ('license', 'copying', 'notice', 'copyright')):
                path = Path(dist.locate_file(file))
                if path.is_file() and path.suffix.casefold() not in ('.py', '.pyc', '.so', '.dll', '.exe'):
                    target = licenses / 'installed' / name / str(file).replace('..', '_')
                    target.parent.mkdir(parents=True, exist_ok=True)
                    shutil.copy2(path, target)
    (licenses / 'build-versions.json').write_text(json.dumps(manifest, ensure_ascii=False, indent=2),
                                                encoding='utf-8')
    qt = qVersion()
    pyside = metadata.version('PySide6-Essentials')
    psutil = metadata.version('psutil')
    source_links = f'''# Corresponding upstream source references for this build

Qt {qt} (QtCore / QtGui / QtWidgets):
https://code.qt.io/cgit/qt/qtbase.git/?h=v{qt}
https://download.qt.io/official_releases/qt/

PySide6 / Shiboken6 {pyside}:
https://code.qt.io/cgit/pyside/pyside-setup.git/?h=v{pyside}
https://download.qt.io/official_releases/QtForPython/

psutil {psutil}:
https://github.com/giampaolo/psutil/tree/release-{psutil}

Python:
https://www.python.org/downloads/source/

No modifications to these upstream libraries are made by this project.
The shared libraries in _internal can be replaced with ABI-compatible versions.
Rebuild scripts and original application source are in the source distribution.
Review all components and the source availability before publishing a release.
'''
    (licenses / 'SOURCES.md').write_text(source_links, encoding='utf-8')


if __name__ == '__main__':
    if len(sys.argv) != 2:
        raise SystemExit('Usage: python scripts/collect_licenses.py <portable-directory>')
    collect(Path(sys.argv[1]))
