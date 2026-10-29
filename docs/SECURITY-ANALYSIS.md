# 0.3.0 — что реализовано и что НЕ гарантируется

Приложение — локальный user-mode инструмент анализа, не EDR/антивирус/песочница.
Слово «подозрительно» означает повод для проверки, не доказанную вредоносность.
Тяжёлые проверки — вручную в фоне. Optional мониторы выключены по умолчанию.

| Запрос | Реальная реализация | Предел / отсутствующая часть |
|---|---|---|
| Hollowing / код в памяти vs EXE | Исполняемые секции главного PE-образа, ASLR HIGHLOW/DIR64, IAT исключён; PEB image base vs PSAPI module base | Не все DLL/память/Python/JIT; не реконструкция hollowed image; JIT/hooks/hotpatch/AV легитимны; нет malware-вердикта |
| Потоки вне модулей/памяти | NtQueryInformationThread Win32 start address, PSAPI module lookup, VirtualQueryEx state/type | Только доступные перечисленные потоки; не поиск всех скрытых kernel/DKOM threads; адреса могут меняться/исчезать |
| Права токена | Enabled/default privileges, elevation/integrity, выделение чувствительных прав | Не устанавливается «необоснованность» прав, права не меняются |
| Критические WinAPI | Просмотр имеющихся Sysmon/Security событий, remote thread/process access/tampering и командные подсказки | Не полный перехват VirtualAllocEx/WriteProcessMemory; Sysmon отдельно устанавливается/настраивается |
| Кейлоггеры / clipboard | Явно обозначенное отсутствие надёжной проверки | WH_KEYBOARD_LL/GetAsyncKeyState/all clipboard hooks не перечисляются; нажатия/clipboard не собираются |
| Random name / hash | Существующий random-name режим одного EXE сохранён | Копия имеет прежний SHA; signed interpreter не модифицируется |
| Anti-kill / Protected Process | Нет | Нет kernel driver/подписи драйвера/PPL; процесс может быть завершён |
| IFEO anti-tampering | Optional read-only наблюдение выбранных значений для regedit/cmd/taskmgr/powershell/pwsh/mmc/taskkill, 32/64 views | Не write protection/авто-repair; IFEO filter subkeys/все приложения не охвачены |
| Threat score | Прозрачный приоритет 0–100, tooltip/CSV, красный ≥60, optional pinning | Не вероятность malware; 0 не значит безопасно; unknown signature/public IP не дают баллов |
| Снимки | Процессы/службы/Run/RunOnce/Startup, optional задания; JSON diff/new-only | Не доказанно чистый baseline; не атомарный полный снимок; один путь EXE не подтверждает неизменность содержимого |
| Карантин | Проверенный ZIP-контейнер .vir до остановки/удаления source EXE | Не переименование сырого PE, но и не VM/sandbox/шифрование/изолированные ACL; образец можно извлечь |
| Hardware / mining | Существующая CPU история + actual NVIDIA NVML GPU load/temp/watts, 60 samples первой GPU, осторожное наблюдение инерции | CPU/AMD/Intel power/temp без провайдера недоступны; нет атрибуции майнинга/скрытого GPU процесса |
| hosts/DNS | SHA-256 hosts; selected TCP/IP registry DNS fields, diff/export | Нет write-blocking/автора изменения; polling пропускает краткие правки; DoH/NRPT/все DNS policies не охвачены |

## Приоритет: точные слагаемые

- +20: подпись проверена и не найдена; +30: подпись признана недействительной.
- +10: CPU процесса в текущем измерении ≥20.
- +40: EXE находится в распознанном Temp.
- +40: нетипичный путь системного имени; +10: необычный родитель shell.
- +25: ручная проверка нашла PEB/module disagreement либо ≥1% и ≥64 различающихся
  байтов исполняемого кода; легитимные hooks остаются возможными.
- +15: ручная проверка нашла старт потока вне перечисленных модулей, в том числе JIT.
- +10: ручная проверка токена нашла включённое чувствительное право.

Сумма ограничена 100. Перечень чувствительных прав: SeDebugPrivilege,
SeImpersonatePrivilege, SeTcbPrivilege, SeLoadDriverPrivilege, SeBackupPrivilege,
SeRestorePrivilege, SeTakeOwnershipPrivilege, SeAssignPrimaryTokenPrivilege.
Нет начисления за public/unknown IP, недоступную/ещё не проверенную подпись,
саму тепловую инерцию. Реального reputation feed для IP в приложении нет.
Результаты ручных проверок привязаны к PID + create_time, не переходят к reused PID.
Это накопленные наблюдения до исчезновения процесса/повторной проверки, не live-AV.
Сортировка списка остаётся ограниченной 5 секундами; по клику — сразу.

## Пределы памяти

Helper — не более 15 с. Только x86/x64 PE, EXE ≤256 МиБ; executable sections
≤32 МиБ, reloc directory ≤2 МиБ/100000 записей, modules ≤2048, threads ≤1024,
regions ≤16384, private executable results ≤128. Страничное чтение 4096 байт;
непрочитанные байты отдельно, сравнение до ~5 с, регионы до ~7 с общего времени.
Частичные/недоступные результаты не заменяются сообщением «чисто».
NtQueryInformationProcess/Thread — низкоуровневые API, совместимость не гарантирована.
Подписи/дампы содержимого памяти не отправляются в сеть и не записываются в файл
автоматически; отображаются количество отличий и примерные RVA/адреса, не raw dump.

## Системное окно

- JSON schema 1, лимит входного снимка 20 МБ, никакого pickle/исполнения JSON.
- Сравнение процессов: exe/name/user, Windows case-insensitive path, PID не ключ.
- Службы сравниваются по конфигурации, не только transient running/stopped.
- Отказ всего раздела/невключённые tasks отмечаются coverage=false и не выдаются
  за удалённые элементы. Даже успешное перечисление может иметь недоступные записи.
- hosts/DNS/IFEO polling ~2 с best effort, audit ~10 с/GPU ~5 с только на активной
  вкладке, один optional worker одновременно. Закрытие окна останавливает polling.
- Event viewer: последние ≤200 событий за 10 минут. Sysmon 1/7/8/10/11/12/13/22/25;
  Security 4688/4672/4719/4946/4947/4948/4950. Пусто ≠ нет активности.
  CommandLine heuristics ограничены несколькими явными строками удаления shadows/
  отключения firewall/recovery, обходов/обфускации/всех способов не охватывают.
- NVML грузится только из System32/nvml.dll. Нет загрузки/установки драйвера.
  Отсутствующий датчик — н/д; предыдущая точка истории не становится текущей.

## Карантин

По явному подтверждению: checked PID/create_time + critical/self/Windows/reparse/UNC
checks → копия EXE ≤512 МиБ в ZIP_STORED sample.bin + metadata.json → CRC/SHA-256
проверка и fsync → повторная проверка identity → terminate → wait ≤4 с → stat/hash
повторно → unlink. Если до verified pack ошибка — процесс не останавливается.
После ошибки остановки/удаления контейнер сохраняется, source может продолжать работу.
Обычные ACL/sharing правила Windows, без принудительного driver-bypass и без защиты
от всех внешних TOCTOU гонок. Контейнер хранит исходный путь/хеш/время и не шифруется.
Папка: %LOCALAPPDATA%\OpenTaskMonitor\quarantine. Авто-restore/execute отсутствуют.
Не извлекайте и не запускайте образцы вне изолированной лаборатории/VM.

Снимки, event logs, пути, имена аккаунтов и контейнеры могут содержать приватные
сведения. Нет автоматической отправки этих данных; отдельно существующий VT —
только opt-in hash-only. Полная модель границ: ../SECURITY.md.
