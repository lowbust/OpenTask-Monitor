# Architecture 0.3.0

- core: immutable snapshots, CSV; metadata has exe/path hints, collection time.
- backend: psutil Collector, metadata cache (15s), CPU/RSS every sample, guarded actions.
- ui/models: incremental ProcessModel (no beginResetModel), numeric sort role.
- ui/window: proxy dynamic sort disabled; periodic 5s resort, batched findings.
- ui/workers: MonitorThread + one bounded SignatureThread, separate QRunnable operations.
- signatures: ctypes WinVerifyTrust file/catalog, offline trust policy, publisher, stat cache.
- inspection: hash-only VT, pure heuristics, network/DLL, kill tree, protected delete.
- handle_probe: isolated read-only NtQuerySystemInformation/NtQueryObject; helper is killed
  after 10s, complete JSONL rows preserved, no target handles closed.
- persistence/startup: Run/RunOnce allowlist + atomic JSON backup; scheduled tasks readonly.
- ui/inspector: process tree snapshot, on-demand DLL/handles/VT, optional selected-process
  network refresh, no background full-machine network/handle scan every tick.
- native launcher: no shell/elevation, optional random copy of pythonw, cleanup on exit.

Signature results are applied with process snapshots, not repeated full repaint per file.
Selected identity is always PID+creation time. Parent links also require older creation time.
JSON backup is write-before-delete, not a registry transaction; external races remain.
SetTcpEntry has no PID argument, so ownership is re-read but not atomic with deletion.
User-facing safety boundaries are documented in README/SECURITY, not hidden as guarantees.

## Unified launcher

One root OpenTaskMonitor.exe reads `launch.ini` via GetPrivateProfileIntW. Qt uses
launch_mode.py to atomically write the same ASCII INI. Selection applies to the
next native launch, never rename-in-place. One-shot CLI overrides are available.
No separate OpenTaskMonitor-Random.exe is emitted by the builder. Runtime helper
executables remain internal dependencies, not separate user entry points.

## Single-file public release

scripts/build_singlefile.py first creates the folder payload, compresses it into
PE resource 202, and builds launcher.c + singlefile.c + miniz reader/inflate.
Runtime bytes are embedded, not fetched at launch. On cold startup singlefile.c
uses Unicode Windows APIs and callback extraction; on warm startup it reuses a
complete per-user cache. Cache ID is application version plus payload SHA prefix.
The marker is written only after extraction; own source/entry launcher are shipped
separately, while dynamic runtime libraries and legal notices stay in the payload.
OPENTASK_PACKAGE_DIR enables Help → licenses; OPENTASK_LAUNCHER protects the original
external EXE from the application's own delete operation. No app data is deleted
when an EXE is moved. Source packaging deliberately excludes builds and binaries.

## Security analysis 0.3.0

- pe_memory: pure x86/x64 PE parsing, executable raw bytes, HIGHLOW/DIR64
  normalization, IAT exclusion, size/count caps; unsupported formats fail explicitly.
- memory_probe: isolated Python child opens QUERY/VM_READ handles, verifies creation
  FILETIME on the actual handle, PSAPI modules, PEB image base, VirtualQueryEx and
  NtQueryInformationThread(ThreadQuerySetWin32StartAddress). No process memory writes.
- forensics: 15-second subprocess bound; Token privileges/elevation/integrity, NVML
  loaded only from explicit System32/nvml.dll. No dependency/driver installation.
- triage: cheap pure additive priority. Manual evidence keyed by PID+creation time,
  pruned when process disappears; no remote-IP reputation or unknown=unsigned shortcut.
- snapshots: JSON schema 1, capped validation, atomic save; process identity for diff
  is exe/name/user (not live PID). Configured collection failures mark coverage false.
- quarantine: stream ZIP_STORED container + metadata, CRC and SHA verification before
  any target termination; stat/hash recheck before unlink, errors retain the container.
- system_watch/event_audit: optional read-only local registry/file/log reads. Audit
  records are not API interception. No key/clipboard capture or automatic registry repair.
- ui/defense: nonmodal system tools, one optional worker at a time, bounded histories,
  timers inactive unless opted in, automatic log/GPU refresh only on the active tab.
  Closing stops timers and waits for tasks. Nonblocking tasks do not blink/disable
  main action buttons; destructive actions remain serialized with blocking tasks.

Snapshots/containers/logs contain private paths/account names/commands. Data is not
signed/encrypted or immune to changes by a same-user/admin adversary. Normal/random
modes use the same source/runtime; the random interpreter copy preserves its hash.
