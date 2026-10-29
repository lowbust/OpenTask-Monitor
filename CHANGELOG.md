# Changelog

## 0.3.0 — 2026-10-28

- On-demand read-only PE executable section comparison with ASLR/IAT handling,
  private executable regions and thread start queries; isolated 15-second helper.
- Read-only token privileges, elevation/integrity, sensitive-right highlighting.
- Explainable investigation priority, optional high-priority pinning, extended CSV.
- JSON system baselines/diff, explicit partial coverage, new-EXE process filtering.
- Verified non-PE quarantine containers before termination/deletion of guarded EXE.
- Optional hosts/DNS/IFEO observation, Windows/Sysmon event viewer, NVIDIA NVML graphs.
- Security polling off by default; separate nonblocking tasks, no added GUI-thread scans.
- No kernel anti-kill, hash randomization, full API/hooks/keylogger/miner detection claims.
- Same one-EXE public distribution and separate matching MIT source archive.

## 0.2.2 — 2026-10-28

- Public portable ZIP contains exactly one OpenTaskMonitor.exe.
- Offline PE-resource payload, native miniz reader, cold-start progress and cached runtime.
- Separate source-only release archive and default GitHub one-file release workflow.
- Help opens embedded license notices/BUILD-INFO after preparation.
- Unified normal/random launch modes and existing inspector features retained.
- Original launcher EXE protected from own delete operation; no kernel driver.

## 0.2.1 — 2026-10-28

- Unified OpenTaskMonitor.exe: normal and random launch modes inside one entry point.
- Menu «Запуск», current mode indicator, atomic preference for next launch.
- Removed separate OpenTaskMonitor-Random.exe from the portable distribution.
- Random mode fallback to normal when runtime is not writable; no privilege bypass.
- One-shot CLI overrides preserved for developers. Existing 0.2.0 features unchanged.

## 0.2.0 — 2026-10-28

- Инкрементальная таблица без reset, ограничение autosort, metadata cache 15 s.
- On-demand inspector: offline WinVerifyTrust + catalog trust, hash-only VirusTotal,
  parent tree, DLL, process sockets и разрыв IPv4 TCP, ограниченный NT handle helper.
- Подсветка необычных путей системных имён и родителей shell; не malware-вердикт.
- Background подписи по флажку, отдельный worker, пакетное применение результатов.
- Kill tree с preflight, delete EXE / delete-on-reboot с защитными ограничениями.
- RunOnce, read-only hidden scheduled tasks inventory; Startup folders read-only.
- Native random-name launcher, не self-defense. Kernel driver не включён.
- Расширенные тесты и явная документация privacy / safety / неполноты API.

## 0.1.0 — 2026-10-28

Первый исходный и embedded portable alpha-релиз: процессы, карточки ресурсов,
службы через sc.exe, Run backup/restore, CSV, журнал, MIT, GitHub workflow.
