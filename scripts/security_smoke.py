"""Developer-only read-only Wine/Windows smoke with the embedded interpreter.

Usage: runtime/python.exe scripts/security_smoke.py <output.json>
No process termination, quarantine deletion, hooks, target registry edits or network.
The GUI may save its own OpenTaskMonitor preferences; QA output files are created.
Exercises own-process memory/token and reports unavailable logs/sensors honestly.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

import psutil
from PySide6.QtCore import QTimer
from PySide6.QtWidgets import QApplication

from opentask import event_audit, snapshots, system_watch
from opentask.forensics import gpu_telemetry, memory_report, token_privileges
from opentask.ui.inspector import Inspector
from opentask.ui.window import MainWindow


def main():
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')
    output = Path(sys.argv[1])
    output.parent.mkdir(parents=True, exist_ok=True)
    process = psutil.Process()
    result = {'pid': process.pid}
    checks = [('memory', lambda: memory_report(process.pid, process.create_time())),
              ('token', lambda: token_privileges(process.pid, process.create_time())),
              ('gpu', gpu_telemetry), ('watch', system_watch.read_state), ('events', event_audit.read_events)]
    for name, check in checks:
        try:
            result[name] = check()
        except Exception as exc:
            result[name] = {'error': str(exc)}
    app = QApplication([])
    window = MainWindow(output.parent / 'security-smoke-data')
    window.show()
    window.open_defense()

    def finish():
        try:
            snapshot = window.last_snapshot
            assert snapshot and snapshot.processes
            captured = snapshots.capture(snapshot.processes, window.data_dir)
            baseline = window.data_dir / 'test-baseline.json'
            snapshots.atomic_json(baseline, captured)
            window.set_baseline(snapshots.load(baseline))
            window.new_only_action.setChecked(True)
            assert window.process_proxy.rowCount() == 0
            window.new_only_action.setChecked(False)
            inspector = Inspector(window, next(row for row in snapshot.processes if row.pid == process.pid))
            assert inspector.tabs.count() == 7
            inspector.close()
            center = window.defense_window
            assert center.tabs.count() == 5
            if 'error' not in result['watch']:
                center.watch_ready(result['watch'])
            center.gpu_ready(result['gpu'])
            result['ui'] = {'processes': len(snapshot.processes), 'baseline_filter': 'passed',
                            'snapshot_errors': captured['errors']}
            assert result['memory'].get('compared_bytes', 0) > 0, result['memory']
            assert result['token'].get('rows'), result['token']
        except Exception as exc:
            result['failure'] = repr(exc)
        finally:
            window.close()
    QTimer.singleShot(2500, finish)
    app.exec()
    output.write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding='utf-8')
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 1 if 'failure' in result else 0


if __name__ == '__main__':
    raise SystemExit(main())
