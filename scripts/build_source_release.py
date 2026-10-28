"""Package only source and build inputs for GitHub; never include runtime/build/EXE."""
from __future__ import annotations

import argparse
import tomllib
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
EXCLUDED = {'.git', '.venv', '__pycache__', '.pytest_cache', '.ruff_cache', 'build', 'dist', 'release',
            'node_modules', '.cache', 'runtime', '.env', '.env.local'}
BINARY_SUFFIXES = {'.exe', '.dll', '.pyd', '.pyc', '.pyo', '.log', '.zip', '.o', '.obj', '.whl'}


def include_source(relative: Path) -> bool:
    return (not any(part in EXCLUDED or part.endswith('.egg-info') for part in relative.parts)
            and relative.suffix.lower() not in BINARY_SUFFIXES)


def package_source(output: Path):
    output.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(output, 'w', zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
        for path in sorted(ROOT.rglob('*')):
            relative = path.relative_to(ROOT)
            if path.is_file() and not path.is_symlink() and include_source(relative):
                archive.write(path, Path('opentask-monitor') / relative)
    with zipfile.ZipFile(output) as archive:
        if archive.testzip() is not None:
            raise RuntimeError('Source archive integrity failed')
    print(f'Ready: {output}')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    version = tomllib.loads((ROOT / 'pyproject.toml').read_text())['project']['version']
    parser.add_argument('--output', type=Path, default=ROOT / f'release/opentask-monitor-{version}-source.zip')
    args = parser.parse_args()
    package_source(args.output.resolve())
