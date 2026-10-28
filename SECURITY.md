# Security — OpenTask Monitor 0.2.2

Локальный диспетчер, не антивирус, EDR или защищённый процесс. Версия alpha.
Подтверждение и denylist снижают риск ошибки, но не гарантируют безопасность.
Kernel драйвера и защиты от TerminateProcess нет.

## Приватность

- VirusTotal — opt-in запрос хеша EXE с ключом в HTTPS header; файл не upload-ится.
- Ключ только в RAM сеанса. Не в логах/настройках/репозитории. Без secure-erasure гарантий.
- Redirect с API-ключом не разрешается. Сервис видит интерес к SHA-256.
- VT 0 detections/404/ошибка API — не основание считать файл безопасным.
- Подписи проверяются offline WinVerifyTrust с cache-only URL retrieval;
  онлайн-проверка отзыва сертификата не выполняется. Root trust задаёт Windows.
- Handles, cmdline, экспорт и логи могут содержать приватные сведения.

## Системные действия

Проверка PID/create_time перед действием не устраняет все гонки. Дерево — снимок,
не атомарное завершение. При suspend продолжают работать другие процессы/драйверы,
ресурсы могут остаться захваченными. Изучение malware — только в изолированной VM.
SetTcpEntry не принимает PID: tuple ownership перечитывается перед вызовом, но
остаётся race; поддерживается только IPv4 TCP, без постоянной блокировки firewall.
Удаление — обычные права и ACL, без bypass/driver. Windows/self paths защищены,
проверяются перенаправления и stat; TOCTOU с внешними программами всё ещё возможен.
После terminate удаление может не удаться. Pending delete при reboot не отменяется
из GUI и может удалить файл позже. Действия необратимы, кроме восстановления Run.

NT handle helper читает File/Key, не закрывает оригинальные target handles и не
изменяет доступ. Запрос имени может зависнуть, поэтому helper изолирован и
ограничен 10 секундами/512 записями. NtQuerySystemInformation/ NtQueryObject —
недокументированные API, полнота и совместимость не гарантируются.

Автозагрузка: allowlist Run/RunOnce, write-before-delete backup. Это не транзакция
файла+реестра. JSON не подписан, содержимое доверено текущему пользователю;
перед восстановлением admin-правами проверяйте команды. Второй экземпляр на
папку данных блокируется. Task Scheduler и Startup folders — read-only.

Random mode меняет имя копии интерпретатора и заголовок. Путь, parent, код и
launcher остаются узнаваемыми. Это не обход защиты/AV, не защита от завершения.
В папке runtime должна быть запись; не используйте общую небезопасную папку.

Для приватных сообщений включите GitHub Private vulnerability reporting и
используйте Security → Advisories. Если его нет, попросите сопровождающего
включить через issue без технических деталей. Не выкладывайте ключи/эксплойты/логи.

## One-EXE cache

The EXE contains an offline compressed payload; no runtime download, shell or
PowerShell extraction. Native miniz reader checks per-file CRC, rejects traversal
components/absolute paths, caps file count and uncompressed size, and writes a
fresh staging directory. A completed payload is renamed into a hash/version cache.
Per-session mutex serializes first preparation. This is not a tamper-proof vault:
the current user can modify their own cache, intentionally allowing replacement
of LGPL DLLs. Do not run binaries/caches from untrusted sources with elevation.
Cold extraction requires disk space; cancellation can leave a partial .staging
folder, never used as the ready cache. Failed/corrupt prepared caches may require
manual cleanup of that build's cache after closing the application. Do not delete
startup-backup.json. No tests of interruption or antivirus quarantine on real
Windows have been performed here.
