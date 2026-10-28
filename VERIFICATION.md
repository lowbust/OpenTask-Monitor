# Проверки 0.2.2 — one-EXE release

Дата 2026-10-28. Linux x64, Wine 10.0/Xvfb; не полноценная Windows VM.

- Ruff успешно; pytest **68 passed**.
- Public portable ZIP has exactly one entry: OpenTaskMonitor.exe. Source packaging
  excludes EXE/DLL/runtime/build/credentials patterns; original external launcher
  is protected by the application's file-delete guard.
- Native PE x64 executable includes compressed resource payload, MIT miniz reader,
  no PowerShell/shell/network extraction.
- Copied EXE into an otherwise empty directory with Cyrillic/spaces: cold startup
  created a user cache, opened GUI, sampled processes and closed with exit 0.
- Warm startup via the same EXE: exit 0, .ready timestamp unchanged (cache reused).
- Random-mode startup via the same EXE/cache: exit 0; random interpreter copy
  removed afterwards. EXE's own directory still contained exactly one file.
- Legal notices, dynamic runtime and BUILD-INFO remain in the payload/cache;
  Help has an explicit command to open them. DLL replacement is not blocked by
  cache verification/restoration on warm launches.
- Both public archives are checked for ZIP integrity. Application source files
  in the embedded payload are compared with the separate source project.

No real Windows 10/11 VM/SmartScreen test, interruption/quarantine recovery, low
space/reparse/concurrent-session edge-case validation, or live VT API query has
been performed here. The extractor checks paths/file limits/CRC but is not an
anti-tamper vault; the current user can modify their cache. Caches/staging leftovers
are not automatically deleted. Do not delete startup-backup.json to clear caches.
First startup is slower than warm startup and requires hundreds of MB disk space.
One-file distribution does not mean zero files created on the user's system.

Previous inspector/launch-mode checks below remain historical evidence, not
additional Windows VM verification for the new build. Kernel driver is absent.

---

# Проверки 0.2.1: единый EXE

Дата 2026-10-28. Среда: Linux x64, Wine 10.0/Xvfb, не настоящая Windows VM.

- Ruff успешно; pytest **65 passed**.
- Новые тесты: default normal, ASCII INI roundtrip, damaged preference fallback,
  creation of data folder, write failure preserves previous setting; Qt menu toggles
  persist the preference. Tests do not modify real Windows services/processes.
- Compiled native Windows x64 launcher; exactly one EXE at package root:
  **OpenTaskMonitor.exe**. No separate Random.exe is produced.
- Same EXE with saved preference 0: GUI smoke exit 0, mode=normal, pythonw.exe.
- Same EXE with saved preference 1: GUI smoke exit 0, mode=random, otm_<random>.exe.
- Preference back to 0: same EXE returns to normal, exit 0.
- Temporary random executable absent after normal exit.
- Menu persistence tested in Qt offscreen. Permission-denied fallback prompt
  implemented but not manually exercised on Windows.
- Application source and portable application .py files are compared at packaging.

This unifies user entry points, not all libraries into one dependency-free file:
`runtime` is still required. Random launch is not protection against termination.
No kernel driver or new network functionality is added. Previous features remain.
Actual Windows 10/11 VM, UAC, HVCI/AV and installer still require manual testing.

---

# Фактические проверки 0.2.0

Дата: 2026-10-28. Среда: Linux x64 + Wine 10.0 + Xvfb, не полноценная Windows VM.

## Исходники

- Ruff: успешно.
- pytest: **60 passed**, Qt offscreen.
- В тестах fake-registry, fake process actions и mock VT; настоящие процессы не
  завершаются, реестры Windows/службы не меняются, API-ключ не нужен.
- Дополнительно проверены modelReset=0 при CPU/RSS updates и удалении строки,
  metadata cache, tree PID reuse, hints, hashing, VT GET без file upload,
  local quota gate, запрет IPv6 disconnect, kill-tree preflight без partial kill.

## Windows binary/API smoke tests через Wine 10.0

Поставка: native x64 EXE + официальный CPython Embedded 3.12.10,
PySide6-Essentials/Shiboken6 6.8.3, psutil 7.2.2. Внешний Python не нужен.

| Проверка | Результат |
|---|---|
| Native launcher → runtime → GUI, --smoke-test | exit 0, процессы получены |
| Random launcher → копия pythonw с новым именем → GUI | exit 0; temporary copy удалена |
| Таблицы процессов/служб, Run inventory, сведения о системе | успешно, ошибок UI не зарегистрировано |
| Inspector / Process Tree | окно и дерево отрисованы |
| WinVerifyTrust у встроенного python.exe | trusted, publisher Python Software Foundation |
| WinVerifyTrust у собственного launcher | unsigned / подпись не найдена (ожидаемо) |
| DLL текущего процесса | получены 44 DLL в тестовом процессе |
| Сеть текущего процесса | вызов успешен, 0 connections в тестовом процессе |
| Изолированный NT handles helper | 28 File/Key записей, около 0.43 s |
| Завершение GUI с обоими worker-потоками | успешно |

Числа описывают среду Wine, не реальную Windows.

## Ограниченная проверка плавности

Синтетический тест: **1500 строк, 21 обновление**, native Windows Qt под Wine,
обновление CPU/RSS плюс обработка Qt events/отрисовка. В одном замере:
первичное заполнение ~535 ms, median следующих обновлений **29.8 ms**, max **37.7 ms**.
Это не доказательство скорости на любом Windows-ПК и не сравнение с baseline 0.1.0.
Главный подтверждённый structural fix — отсутствие model reset и постоянной
пересортировки на каждом dataChanged, metadata cache и on-demand тяжёлые проверки.

## Не проверено здесь

- Настоящая Windows 10/11: UAC, protected processes, разные trust stores/revocation,
  catalog-only signed files на реальной установке и ошибки сети.
- Живой VirusTotal с личным API-ключом (проверен mock transport, ключ не запрашивался).
- Настоящий Get-ScheduledTask: PowerShell отсутствует в среде Wine.
- Разрыв реального пользовательского TCP, kill tree, unlink EXE, pending delete,
  изменение RunOnce и stop реальных системных служб: только mocks/ручной чек-лист.
- HVCI/AV/SmartScreen/DPI на целевых Windows, подпись собственного бинарника.
- Альтернативный PyInstaller/Inno Setup workflow и installer.

В готовой поставке нет kernel driver. Возможности с ограничениями описаны в
README.md и docs/TESTING.md. Изучение malware только в изолированной VM.
