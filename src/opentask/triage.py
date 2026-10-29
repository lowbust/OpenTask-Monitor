"""Transparent investigation-priority heuristic, NOT malware probability."""
from __future__ import annotations

import ntpath
from functools import lru_cache


@lru_cache(maxsize=8192)
def in_temp(path: str, temp: str) -> bool:
    if not path:
        return False
    value = ntpath.normcase(ntpath.normpath(path))
    roots = [ntpath.normcase(ntpath.normpath(temp)), r'c:\windows\temp']
    return any(value.startswith(root.rstrip('\\') + '\\') for root in roots if root)


def priority(row, signature=None, evidence=None, temp=r'C:\Users\User\AppData\Local\Temp'):
    evidence = evidence or {}
    reasons = []
    def add(points, note):
        reasons.append((points, note))
    if signature and signature.status == 'подпись не найдена':
        add(20, 'нет найденной подписи')
    if signature and signature.status == 'подпись недействительна':
        add(30, 'подпись недействительна')
    if row.cpu >= 20:
        add(10, 'высокая доля CPU в текущем измерении')
    if in_temp(row.exe, temp):
        add(40, 'EXE в Temp')
    if 'нетипичный путь' in row.findings:
        add(40, 'нетипичный путь системного имени')
    if 'проверьте родителя' in row.findings:
        add(10, 'необычный родитель shell')
    if evidence.get('memory_difference'):
        add(25, 'по ручной проверке различается исполняемый код (возможны легитимные hooks)')
    if evidence.get('thread_outside'):
        add(15, 'по ручной проверке старт потока вне перечисленных модулей (возможен JIT)')
    if evidence.get('sensitive_token'):
        add(10, 'включено чувствительное право токена (может быть необходимо)')
    # "Unknown/public IP" alone deliberately receives no points. No reputation feed is present.
    return min(100, sum(points for points, _ in reasons)), '; '.join(f'+{p}: {text}' for p, text in reasons)
