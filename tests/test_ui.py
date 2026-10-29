import os
import threading

os.environ.setdefault('QT_QPA_PLATFORM', 'offscreen')

import pytest
from PySide6.QtCore import (
    QCoreApplication,
    QEvent,
    QEventLoop,
    QObject,
    QSettings,
    Qt,
    QThreadPool,
    QTimer,
    Signal,
)
from PySide6.QtWidgets import QApplication

from opentask.core import ProcessRow, Snapshot
from opentask.ui.models import ProcessModel, SearchProxy
from opentask.ui.workers import Task


@pytest.fixture(scope='module')
def app():
    application = QApplication.instance() or QApplication([])
    yield application


def rows():
    return [ProcessRow(20, 1, 'Beta.exe', 'test', 9, 1024, 1, 'running', 10),
            ProcessRow(10, 1, 'Alpha.exe', 'test', 80, 1024**2, 5, 'running', 20)]


def test_numeric_sort_and_filter(app):
    model = ProcessModel()
    model.replace(rows())
    proxy = SearchProxy()
    proxy.setSourceModel(model)
    proxy.sort(2, Qt.SortOrder.AscendingOrder)
    assert proxy.index(0, 0).data() == 'Beta.exe'
    proxy.sort(3, Qt.SortOrder.DescendingOrder)
    assert proxy.index(0, 0).data() == 'Alpha.exe'
    proxy.set_query('ALPHA test')
    assert proxy.rowCount() == 1
    proxy.set_query('not-found')
    assert proxy.rowCount() == 0


def test_task_result_and_error(app):
    result, errors, finished = [], [], []
    task = Task(lambda: 42)
    task.signals.result.connect(result.append)
    task.signals.finished.connect(lambda: finished.append(True))
    task.run()
    assert result == [42] and finished == [True]
    def failure():
        raise PermissionError('test denied')
    task = Task(failure)
    task.signals.error.connect(errors.append)
    task.run()
    assert 'PermissionError' in errors[0]


class SilentMonitor(QObject):
    snapshot = Signal(object)
    error = Signal(str)

    def __init__(self, parent=None):
        super().__init__(parent)
        self.paused = threading.Event()
        self.interval = 1.5

    def start(self):
        pass

    def stop(self):
        pass

    def isRunning(self):
        return False


def test_window_smoke_selection_pause(app, tmp_path, monkeypatch):
    import opentask.ui.window as window_module
    monkeypatch.setattr(window_module, 'MonitorThread', SilentMonitor)
    # Never touch the real Windows QSettings registry in tests.
    QSettings.setDefaultFormat(QSettings.Format.IniFormat)
    QSettings.setPath(QSettings.Format.IniFormat, QSettings.Scope.UserScope, str(tmp_path))
    window = window_module.MainWindow(tmp_path)
    window.show()
    snapshot = Snapshot(tuple(rows()), 25, 50, 4 * 1024**3, 8 * 1024**3, 1024, 512, 0, 0, 1)
    window.on_snapshot(snapshot)
    window.search.setText('Alpha')
    assert window.process_proxy.rowCount() == 1
    window.process_table.selectRow(0)
    window.on_snapshot(snapshot)
    assert window.selected_process_silent() == (10, 20)
    actions = []
    monkeypatch.setattr(window, 'confirm', lambda *_: True)
    monkeypatch.setattr(window_module, 'process_action',
                        lambda pid, created, action: actions.append((pid, created, action)) or 'fake OK')
    monkeypatch.setattr(window, 'run_task', lambda fn, callback=None: callback(fn()))
    for button in window.action_buttons:
        if button.text() in ('Приостановить процесс', 'Возобновить', 'Завершить процесс'):
            button.click()
    assert [action[2] for action in actions] == ['suspend', 'resume', 'terminate']
    assert all(action[:2] == (10, 20) for action in actions)
    window.pause_button.setChecked(True)
    assert window.monitor.paused.is_set()
    window.pause_button.setChecked(False)
    assert not window.monitor.paused.is_set()
    window.interval.setCurrentText('2.0 с')
    assert window.monitor.interval == 2
    from opentask.launch_mode import random_enabled
    window.random_launch_action.setChecked(True)
    assert random_enabled(tmp_path)
    window.random_launch_action.setChecked(False)
    assert not random_enabled(tmp_path)
    window.close()
    app.processEvents()
    assert not window.isVisible()
    window.deleteLater()
    QCoreApplication.sendPostedEvents(None, QEvent.Type.DeferredDelete)
    app.processEvents()


def test_worker_callbacks_are_on_gui_thread(app):
    main_thread = threading.get_ident()
    received = []
    loop = QEventLoop()
    pool = QThreadPool()
    task = Task(threading.get_ident)
    task.signals.result.connect(lambda worker_id: received.append((worker_id, threading.get_ident())))
    task.signals.finished.connect(loop.quit)
    timeout = QTimer()
    timeout.setSingleShot(True)
    timeout.timeout.connect(loop.quit)
    timeout.start(5000)
    pool.start(task)
    loop.exec()
    assert pool.waitForDone(5000)
    assert received and received[0][0] != main_thread
    assert received[0][1] == main_thread


def test_incremental_model_keeps_selection_without_reset(app):
    from dataclasses import replace

    from PySide6.QtCore import QPersistentModelIndex
    model = ProcessModel()
    resets = []
    model.modelReset.connect(lambda: resets.append(True))
    model.replace(rows())
    persistent = QPersistentModelIndex(model.index(0, 0))
    model.replace([replace(row, cpu=row.cpu + 1, memory=row.memory + 1024) for row in rows()])
    assert persistent.isValid()
    assert persistent.data() == 'Beta.exe'
    assert resets == []
    model.replace([replace(rows()[1], cpu=10)])
    assert not persistent.isValid()
    assert resets == []


def test_priority_pinning_new_only_filter_and_color(app):
    from dataclasses import replace

    from opentask.snapshots import process_key
    model = ProcessModel()
    model.replace([replace(rows()[0], triage=60, exe=r'C:\Apps\Beta.exe'),
                   replace(rows()[1], triage=10, exe=r'C:\Apps\Alpha.exe')])
    proxy = SearchProxy()
    proxy.setSourceModel(model)
    for direction in (Qt.SortOrder.AscendingOrder, Qt.SortOrder.DescendingOrder):
        proxy.sort(2, direction)
        assert proxy.index(0, 0).data() == 'Beta.exe'
    assert model.data(model.index(0, 0), Qt.ItemDataRole.ForegroundRole).name() == '#ff8b8b'
    proxy.pin_high = False
    proxy.invalidate()
    proxy.sort(2, Qt.SortOrder.DescendingOrder)
    assert proxy.index(0, 0).data() == 'Alpha.exe'
    proxy.new_only = True
    proxy.baseline_keys = {process_key(model.rows[1])}
    proxy.invalidate()
    assert proxy.rowCount() == 1 and proxy.index(0, 0).data() == 'Beta.exe'


def test_security_dialogs_construct_no_background_security_scans(app, tmp_path, monkeypatch):
    import opentask.ui.window as window_module
    from opentask.ui.inspector import Inspector
    monkeypatch.setattr(window_module, 'MonitorThread', SilentMonitor)
    QSettings.setDefaultFormat(QSettings.Format.IniFormat)
    QSettings.setPath(QSettings.Format.IniFormat, QSettings.Scope.UserScope, str(tmp_path))
    window = window_module.MainWindow(tmp_path)
    window.open_defense()
    center = window.defense_window
    assert center.tabs.count() == 5
    assert not any(check.isChecked() for check in (center.watch_check, center.audit_check, center.gpu_check))
    assert not window.tasks
    center.gpu_ready({'devices': [{'name': 'fixture GPU', 'gpu_percent': 90, 'temperature_C': 70, 'power_W': 100}]})
    center.gpu_ready({'devices': [{'name': 'fixture GPU', 'gpu_percent': 10, 'temperature_C': 69, 'power_W': 25}]})
    assert 'НЕ доказательство' in center.hardware_text.toPlainText()
    center.gpu_ready({'devices': [], 'note': 'unavailable'})
    assert center.gpu_load.value == 'н/д' and center.previous_gpu is None
    inspector = Inspector(window, rows()[0])
    assert inspector.tabs.count() == 7 and not inspector.busy
    inspector.close()
    center.close()
    app.processEvents()
    window.close()
    window.deleteLater()
    QCoreApplication.sendPostedEvents(None, QEvent.Type.DeferredDelete)
    app.processEvents()


def test_nonblocking_monitor_tasks_do_not_disable_main_actions(app, tmp_path, monkeypatch):
    import opentask.ui.window as window_module
    monkeypatch.setattr(window_module, 'MonitorThread', SilentMonitor)
    QSettings.setDefaultFormat(QSettings.Format.IniFormat)
    QSettings.setPath(QSettings.Format.IniFormat, QSettings.Scope.UserScope, str(tmp_path))
    window = window_module.MainWindow(tmp_path)
    monkeypatch.setattr(window.pool, 'start', lambda _: None)
    window.run_task(lambda: 'readonly', block_actions=False)
    assert window.tasks and not window.blocking_tasks
    assert all(button.isEnabled() for button in window.action_buttons)
    next(iter(window.tasks)).run()
    assert not window.tasks
    window.run_task(lambda: 'blocking')
    assert window.blocking_tasks and not any(button.isEnabled() for button in window.action_buttons)
    next(iter(window.tasks)).run()
    assert not window.blocking_tasks
    window.close()
    window.deleteLater()
    QCoreApplication.sendPostedEvents(None, QEvent.Type.DeferredDelete)
    app.processEvents()
