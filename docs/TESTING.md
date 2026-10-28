# Testing 0.2.2

## Автоматические тесты

`python -m ruff check .` и `QT_QPA_PLATFORM=offscreen python -m pytest -q`.
Unit tests не завершают настоящие процессы и не меняют реальный Run/SCM.
Проверены CSV, PID identity, backup/restore, no-reset incremental Qt model,
metadata cache, parent/reused PID, эвристика пути, hash-only VT (mock), rate limit,
IPv6 disconnect rejection, kill-tree preflight и потоковая доставка callbacks.

## Перед распространением — Windows VM, не рабочая машина

- [ ] Обычный native EXE, random launcher, кириллица/пробелы в путях.
- [ ] 500/1500/3000 процессов: плавность scrolling/select, интервалы 0.5/1.5/5 s.
- [ ] Модели не сбрасывают selection; сортировка каждые 5 s и сразу по клику.
- [ ] PID reuse не даёт ложного родителя/действия над другим процессом.
- [ ] Подпись Microsoft, стороннего signed exe, unsigned exe, повреждённого signed file.
- [ ] Catalog-only файл: не объявлять unsigned, если catalog verify недоступна.
- [ ] Включить фоновые подписи, проверить доступ denied/UNC и корректный выход.
- [ ] Собственный VT test-key: известный hash, unknown hash (404), 401/403/429,
      отсутствие API-ключа в логах/настройках. Не upload файлов.
- [ ] Process Tree: shell из Explorer/IDE/службы, пропавший родитель и PID reuse.
- [ ] DLL текущего/защищённого процесса: корректный список или понятный AccessDenied.
- [ ] IPv4 TCP в тестовой программе: разрыв admin/отказ без elevation,
      UDP/IPv6 не допускаются, приложение вправе переподключиться.
- [ ] Handles File/Key: own/foreign process, отсутствие hangs GUI, 10-second timeout,
      частичные записи и NT paths. Не считать каждый handle «заблокированным».
- [ ] Suspend/resume только disposable notepad, затем принудительное завершение.
- [ ] Kill tree на тестовом родителе с потомками, отказ для ancestors/self/critical.
- [ ] Удаление только disposable test EXE в VM, проверить unlink failure/locked file.
- [ ] Защита Windows/self/symlink/UNC; pending-delete на тестовом файле перед snapshot restore.
- [ ] Run и RunOnce REG_SZ/REG_EXPAND_SZ HKCU/HKLM 32/64, restore after restart/conflict.
- [ ] ScheduledTask hidden read-only inventory с Get-ScheduledTask; Startup folders readonly.
- [ ] SCM start/stop только disposable test service. Не системные службы.
- [ ] Закрытие во время VT/handles/signature worker ждёт tasks, не убивает GUI-потоки.
- [ ] Чистая VM без Python/интернета, DPI 100/150/200%, Defender / SmartScreen.
- [ ] License audit и проверка актуальности компонентов перед production.

Под Wine можно проверить много API, но это не равнозначно полноценной Windows.
Деструктивные операции не подтверждены на настоящей Windows в среде подготовки.
Kernel driver отсутствует и не тестируется. Источник результатов — VERIFICATION.md.

## Unified launcher 0.2.2

- [ ] One root OpenTaskMonitor.exe, no separate Random executable.
- [ ] Toggle menu on → close → same EXE starts with random interpreter name/title.
- [ ] Toggle menu off → close → same EXE returns to normal mode.
- [ ] Settings roundtrip; temporary copy removed on normal exit.
- [ ] Read-only runtime: fallback prompt, no destructive permission changes.
- [ ] No changes to startup-backup.json when changing launch preference.

## One-EXE release 0.2.2

- [ ] Public portable ZIP contains exactly OpenTaskMonitor.exe.
- [ ] Cold launch from an otherwise empty Unicode path prepares user cache offline.
- [ ] Warm launch leaves .ready timestamp unchanged and creates no adjacent files.
- [ ] Random and normal modes work using that same EXE and cache.
- [ ] Legal files/BUILD-INFO are present; Help opens their folder.
- [ ] Cancellation, low disk space, unreadable AppData, concurrent launches,
      interrupted extraction, quarantine recovery — manually test on Windows VM.
- [ ] LGPL-compatible library replacement without forced restoration on warm launch.
- [ ] Repository Code has source, Releases has the one-EXE portable, no runtime in git.
