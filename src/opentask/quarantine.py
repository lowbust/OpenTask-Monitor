"""Quarantine is a non-PE ZIP container, not a virtual machine/security sandbox.

No automatic execution or extraction. Ordinary Windows ACL/sharing rules apply.
A .vir extension alone would NOT stop CreateProcess from executing a raw PE.
"""
from __future__ import annotations

import hashlib
import json
import os
import time
import uuid
import zipfile
from pathlib import Path

from opentask.backend import OperationError, checked_process
from opentask.inspection import hash_file, safe_delete_path


def pack_file(path: Path, destination: Path, metadata=None):
    before = path.stat()
    if before.st_size > 512 * 1024 * 1024:
        raise OperationError('Файл больше 512 МиБ — предел контейнера карантина.')
    digest = hash_file(str(path))
    metadata = dict(metadata or {})
    metadata.update({'schema': 1, 'original_path': str(path), 'sha256': digest,
                     'size': before.st_size, 'captured_at': time.time(),
                     'warning': 'Контейнер, не sandbox. Не извлекайте и не запускайте образец на рабочей машине.'})
    temporary = destination.with_suffix('.tmp')
    destination.parent.mkdir(parents=True, exist_ok=True)
    try:
        with zipfile.ZipFile(temporary, 'w', zipfile.ZIP_STORED, strict_timestamps=False) as archive:
            archive.write(path, 'sample.bin')
            archive.writestr('metadata.json', json.dumps(metadata, ensure_ascii=False, indent=2))
        with zipfile.ZipFile(temporary) as archive:
            if archive.testzip() is not None:
                raise OperationError('Ошибка целостности контейнера.')
            check = hashlib.sha256()
            with archive.open('sample.bin') as stream:
                for block in iter(lambda: stream.read(1024 * 1024), b''):
                    check.update(block)
            if check.hexdigest() != digest:
                raise OperationError('Файл изменился во время копирования.')
        if hash_file(str(path)) != digest:
            raise OperationError('Источник изменился во время копирования; удаление запрещено.')
        with temporary.open('r+b') as stream:
            os.fsync(stream.fileno())
        os.replace(temporary, destination)
        return metadata
    finally:
        if temporary.exists():
            temporary.unlink()


def quarantine_process(pid: int, created: float, data_dir: Path):
    process = checked_process(pid, created, mutation=True)
    path = safe_delete_path(process.exe())
    identity = path.stat()
    destination = data_dir / 'quarantine' / (uuid.uuid4().hex + '.vir')
    metadata = pack_file(path, destination, {'pid': pid, 'created': created})
    # Only after verified durable backup exists do we stop/remove the source.
    try:
        checked_process(pid, created, mutation=True).terminate()
        process.wait(timeout=4)
        after = path.stat()
        if (identity.st_size, identity.st_ino, identity.st_mtime_ns) != (after.st_size, after.st_ino, after.st_mtime_ns):
            raise OperationError('Источник заменён после копирования. Контейнер сохранён, удаление отменено.')
        if hash_file(str(path)) != metadata['sha256']:
            raise OperationError('Хеш источника изменился; контейнер сохранён, удаление отменено.')
        path.unlink()
    except Exception as exc:
        raise OperationError(f'Копия в {destination} сохранена, но источник не удалён: {exc}') from None
    return ('Процесс завершён, исходный EXE удалён; образец в контейнере ' + str(destination) +
            '. Это не песочница; извлечение/запуск только в изолированной лаборатории.')
