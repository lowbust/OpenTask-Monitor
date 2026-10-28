from __future__ import annotations

import logging
import os
import sys
import time
from dataclasses import replace
from functools import partial
from pathlib import Path

from PySide6.QtCore import QSettings, Qt, QThreadPool, QTimer
from PySide6.QtGui import QAction, QKeySequence
from PySide6.QtWidgets import (
    QApplication,
    QComboBox,
    QDialog,
    QDialogButtonBox,
    QFileDialog,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QMainWindow,
    QMenu,
    QMessageBox,
    QPlainTextEdit,
    QPushButton,
    QTableView,
    QTabWidget,
    QVBoxLayout,
    QWidget,
)

from opentask import __version__
from opentask.backend import (
    is_admin,
    list_services,
    process_action,
    process_details,
    service_action,
    show_process_file,
    system_info,
)
from opentask.core import human_bytes, processes_csv
from opentask.inspection import RateLimit, kill_tree, parent_findings, path_findings, remove_file
from opentask.launch_mode import random_enabled, set_random_enabled
from opentask.persistence import scheduled_tasks
from opentask.startup import BackupStore, StartupManager, WinRegistry, folder_entries
from opentask.ui.inspector import Inspector
from opentask.ui.models import ProcessModel, SearchProxy, TableModel
from opentask.ui.widgets import MetricCard
from opentask.ui.workers import MonitorThread, SignatureThread, Task


class MainWindow(QMainWindow):
    def __init__(self, data_dir: Path):
        super().__init__()
        self.data_dir = data_dir
        self.setWindowTitle(f"OpenTask Monitor {__version__}")
        self.resize(1280, 850)
        self.setMinimumSize(1000, 700)
        self.settings = QSettings("OpenTaskMonitor", "OpenTaskMonitor")
        geometry = self.settings.value("geometry")
        if geometry is not None:
            self.restoreGeometry(geometry)
        self.pool = QThreadPool(self)
        self.pool.setMaxThreadCount(3)
        self.tasks = set()
        self.action_buttons = []
        self.last_snapshot = None
        self.vt_key = ''
        self.vt_limit = RateLimit()
        self.signature_results = {}
        self.signature_enqueue_time = 0
        self.signature_worker = SignatureThread(self)
        self.signature_worker.result.connect(self.signature_received)
        self.signature_worker.start()
        self.last_sort_time = 0
        self.has_services = False
        self.has_startup = False
        self.monitor = MonitorThread(self)
        self.build_ui()
        self.build_menu()
        self.monitor.snapshot.connect(self.on_snapshot)
        self.monitor.error.connect(self.report_error)
        self.interval.setCurrentText(str(self.settings.value("interval", "1.5")) + " с")
        self.monitor.start()

    def build_ui(self):
        central = QWidget()
        root = QVBoxLayout(central)
        root.setContentsMargins(22, 16, 22, 12)
        root.setSpacing(14)
        heading = QHBoxLayout()
        titles = QVBoxLayout()
        title = QLabel("OpenTask Monitor")
        title.setObjectName("title")
        subtitle = QLabel("ПРОЦЕССЫ  /  СЛУЖБЫ  /  АВТОЗАГРУЗКА")
        subtitle.setObjectName("subtitle")
        titles.addWidget(title)
        titles.addWidget(subtitle)
        heading.addLayout(titles)
        heading.addStretch()
        badge = QLabel("Администратор" if is_admin() else "Обычный доступ")
        badge.setObjectName("badge")
        badge.setToolTip("Для изменения защищённых процессов, служб и HKLM запустите программу от администратора.")
        heading.addWidget(badge, alignment=Qt.AlignmentFlag.AlignVCenter)
        root.addLayout(heading)
        metrics = QHBoxLayout()
        self.cpu_card = MetricCard("ПРОЦЕССОР", "#79b8ff")
        self.memory_card = MetricCard("ОПЕРАТИВНАЯ ПАМЯТЬ", "#b49aff")
        self.net_card = MetricCard("СЕТЬ · ПРИЁМ", "#63ddbc")
        self.disk_card = MetricCard("ДИСК · ЧТЕНИЕ", "#ffbf79")
        for card in (self.cpu_card, self.memory_card, self.net_card, self.disk_card):
            metrics.addWidget(card)
        root.addLayout(metrics)
        toolbar = QHBoxLayout()
        self.search = QLineEdit()
        self.search.setPlaceholderText("Поиск по имени, PID, пользователю…   Ctrl+F")
        self.search.setClearButtonEnabled(True)
        self.search.textChanged.connect(self.filter_current)
        toolbar.addWidget(self.search, 1)
        toolbar.addWidget(QLabel("Интервал:"))
        self.interval = QComboBox()
        self.interval.addItems(["0.5 с", "1.0 с", "1.5 с", "2.0 с", "5.0 с"])
        self.interval.setCurrentText("1.5 с")
        self.interval.currentTextChanged.connect(self.change_interval)
        toolbar.addWidget(self.interval)
        self.signature_toggle = QAction('Фоновые подписи (offline)', self)
        self.signature_toggle.setCheckable(True)
        self.signature_toggle.toggled.connect(self.signature_enabled)
        self.pause_button = QPushButton("Приостановить")
        self.pause_button.setCheckable(True)
        self.pause_button.toggled.connect(self.pause)
        toolbar.addWidget(self.pause_button)
        root.addLayout(toolbar)
        self.tabs = QTabWidget()
        self.tabs.addTab(self.build_process_tab(), "Процессы")
        self.tabs.addTab(self.build_service_tab(), "Службы")
        self.tabs.addTab(self.build_startup_tab(), "Автозагрузка")
        self.tabs.addTab(self.build_system_tab(), "Система")
        self.tabs.addTab(self.build_log_tab(), "Журнал")
        self.tabs.currentChanged.connect(self.tab_changed)
        root.addWidget(self.tabs, 1)
        self.setCentralWidget(central)
        self.statusBar().showMessage("Сбор данных… Первая оценка нагрузки процессов появится со второго измерения.")

    def make_table(self, model):
        proxy = SearchProxy(self)
        proxy.setSourceModel(model)
        table = QTableView()
        table.setModel(proxy)
        table.setAlternatingRowColors(True)
        table.setSelectionBehavior(QTableView.SelectionBehavior.SelectRows)
        table.setSelectionMode(QTableView.SelectionMode.SingleSelection)
        table.setEditTriggers(QTableView.EditTrigger.NoEditTriggers)
        table.setSortingEnabled(True)
        table.setShowGrid(False)
        table.verticalHeader().hide()
        table.verticalHeader().setDefaultSectionSize(32)
        table.horizontalHeader().setStretchLastSection(True)
        table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Interactive)
        table.sortByColumn(0, Qt.SortOrder.AscendingOrder)
        return table, proxy

    def button(self, text, callback, *, dangerous=False):
        button = QPushButton(text)
        button.clicked.connect(callback)
        if dangerous:
            button.setObjectName("danger")
        self.action_buttons.append(button)
        return button

    def build_process_tab(self):
        page = QWidget()
        layout = QVBoxLayout(page)
        self.process_model = ProcessModel(self)
        self.process_table, self.process_proxy = self.make_table(self.process_model)
        for col, size in enumerate((200, 65, 80, 115, 75, 160, 95, 65, 300, 370)):
            self.process_table.setColumnWidth(col, size)
        self.process_table.sortByColumn(2, Qt.SortOrder.DescendingOrder)
        self.process_proxy.setDynamicSortFilter(False)
        self.process_table.doubleClicked.connect(self.show_details)
        self.process_table.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.process_table.customContextMenuRequested.connect(self.process_menu)
        layout.addWidget(self.process_table)
        buttons = QHBoxLayout()
        buttons.addWidget(self.button("Анализ…", self.inspect_process))
        buttons.addWidget(self.button("Свойства", self.show_details))
        buttons.addWidget(self.button("Открыть расположение", self.open_file))
        buttons.addWidget(self.button("Приоритет…", self.priority_menu))
        buttons.addWidget(self.button("Приостановить процесс", partial(self.mutate_process, "suspend")))
        buttons.addWidget(self.button("Возобновить", partial(self.mutate_process, "resume")))
        buttons.addStretch()
        buttons.addWidget(self.button("Завершить процесс", partial(self.mutate_process, "terminate"), dangerous=True))
        layout.addLayout(buttons)
        return page

    def build_service_tab(self):
        page = QWidget()
        layout = QVBoxLayout(page)
        notice = QLabel("Запуск и остановка обычно требуют прав администратора. Зависимые службы автоматически не останавливаются.")
        notice.setWordWrap(True)
        notice.setObjectName("notice")
        layout.addWidget(notice)
        keys = ["name", "display_name", "status", "start_type", "pid", "username", "binpath"]
        self.service_model = TableModel(
            ["Имя", "Описание", "Состояние", "Тип запуска", "PID", "Учётная запись", "Путь"],
            lambda row, col: row.get(keys[col], "") if row.get(keys[col]) is not None else "", self,
        )
        self.service_table, self.service_proxy = self.make_table(self.service_model)
        self.service_table.setColumnWidth(0, 180)
        self.service_table.setColumnWidth(1, 280)
        layout.addWidget(self.service_table)
        buttons = QHBoxLayout()
        buttons.addWidget(self.button("Обновить", self.refresh_services))
        buttons.addStretch()
        buttons.addWidget(self.button("Запустить", partial(self.mutate_service, "start")))
        buttons.addWidget(self.button("Остановить…", partial(self.mutate_service, "stop"), dangerous=True))
        layout.addLayout(buttons)
        return page

    def build_startup_tab(self):
        page = QWidget()
        layout = QVBoxLayout(page)
        notice = QLabel("Run / RunOnce: HKCU и HKLM (64/32 бит), отключение с резервной копией. Папки Startup — просмотр.\n"
                        "Задания планировщика — отдельный read-only список. Службы — вкладка «Службы». Не все виды persistence охвачены.")
        notice.setObjectName("notice")
        notice.setWordWrap(True)
        layout.addWidget(notice)

        def value(row, col):
            return (row.name, "Включено" if row.enabled else "Отключено (копия)", row.location,
                    row.command, "Да" if row.editable else "Только просмотр")[col]

        self.startup_model = TableModel(["Имя", "Состояние", "Источник", "Команда / путь", "Изменение"], value, self)
        self.startup_table, self.startup_proxy = self.make_table(self.startup_model)
        for col, size in enumerate((190, 170, 120, 460, 120)):
            self.startup_table.setColumnWidth(col, size)
        layout.addWidget(self.startup_table)
        buttons = QHBoxLayout()
        buttons.addWidget(self.button("Обновить", self.refresh_startup))
        buttons.addWidget(self.button("Копировать команду", self.copy_startup))
        buttons.addWidget(self.button("Планировщик задач…", self.task_inventory))
        buttons.addStretch()
        buttons.addWidget(self.button("Включить / отключить…", self.toggle_startup))
        layout.addLayout(buttons)
        return page

    def build_system_tab(self):
        page = QWidget()
        layout = QVBoxLayout(page)
        self.system_text = QPlainTextEdit()
        self.system_text.setReadOnly(True)
        layout.addWidget(self.system_text)
        layout.addWidget(self.button("Обновить сведения", self.refresh_system), alignment=Qt.AlignmentFlag.AlignLeft)
        return page

    def build_log_tab(self):
        page = QWidget()
        layout = QVBoxLayout(page)
        label = QLabel("Журнал текущего сеанса. Файл диагностики: " + str(self.data_dir / "opentask.log"))
        label.setWordWrap(True)
        layout.addWidget(label)
        self.log_text = QPlainTextEdit()
        self.log_text.setReadOnly(True)
        self.log_text.setMaximumBlockCount(1500)
        layout.addWidget(self.log_text)
        return page

    def build_menu(self):
        file_menu = self.menuBar().addMenu("Файл")
        export = QAction("Экспорт видимых процессов в CSV…", self)
        export.setShortcut(QKeySequence("Ctrl+S"))
        export.triggered.connect(self.export_csv)
        file_menu.addAction(export)
        exit_action = QAction("Выход", self)
        exit_action.setShortcut(QKeySequence("Alt+F4"))
        exit_action.triggered.connect(self.close)
        file_menu.addAction(exit_action)
        view = self.menuBar().addMenu("Вид")
        search_action = QAction("Поиск", self)
        search_action.setShortcut(QKeySequence("Ctrl+F"))
        search_action.triggered.connect(self.search.setFocus)
        view.addAction(search_action)
        refresh = QAction("Обновить текущую вкладку", self)
        refresh.setShortcut(QKeySequence("F5"))
        refresh.triggered.connect(self.refresh_current)
        view.addAction(refresh)
        launch_menu = self.menuBar().addMenu('Запуск')
        current_mode = 'случайное имя' if '--random-title' in sys.argv else 'обычный'
        current = launch_menu.addAction('Текущий запуск: ' + current_mode)
        current.setEnabled(False)
        self.random_launch_action = QAction('Случайное имя при следующем запуске', self)
        self.random_launch_action.setCheckable(True)
        self.random_launch_action.setChecked(random_enabled(self.data_dir))
        self.random_launch_action.setToolTip('Настройка для единого OpenTaskMonitor.exe в embedded portable-сборке.')
        self.random_launch_action.setEnabled(not getattr(sys, 'frozen', False))
        self.random_launch_action.toggled.connect(self.change_launch_mode)
        launch_menu.addAction(self.random_launch_action)
        launch_menu.addAction('Как переключить режим…', self.launch_mode_help)
        tools = self.menuBar().addMenu('Инструменты')
        tools.addAction('Анализ выбранного процесса…', self.inspect_process)
        tools.addAction(self.signature_toggle)
        tools.addAction('Завершить дерево выбранного процесса…', self.kill_selected_tree)
        tools.addSeparator()
        tools.addAction('Завершить и удалить EXE без корзины…', partial(self.delete_selected_file, False))
        tools.addAction('Удалить EXE при перезагрузке…', partial(self.delete_selected_file, True))
        tools.addSeparator()
        tools.addAction('Забыть API-ключ VirusTotal', self.forget_vt_key)
        help_menu = self.menuBar().addMenu("Справка")
        about = QAction("О программе", self)
        about.triggered.connect(self.about)
        help_menu.addAction(about)
        help_menu.addAction('Лицензии и сведения о сборке…', self.open_licenses)

    def change_interval(self, text):
        try:
            value = float(text.split()[0])
        except (ValueError, IndexError):
            return
        if value not in (0.5, 1.0, 1.5, 2.0, 5.0):
            return
        self.monitor.interval = value
        self.settings.setValue("interval", str(value))

    def pause(self, paused):
        if paused:
            self.monitor.paused.set()
        else:
            self.monitor.paused.clear()
        self.pause_button.setText("Продолжить" if paused else "Приостановить")
        self.log("Мониторинг приостановлен." if paused else "Мониторинг продолжен.")

    def filter_current(self, text):
        index = self.tabs.currentIndex()
        proxies = [self.process_proxy, self.service_proxy, self.startup_proxy]
        if index < len(proxies):
            proxies[index].set_query(text)

    def tab_changed(self, index):
        self.search.setEnabled(index < 3)
        self.filter_current(self.search.text())
        if index == 1 and not self.has_services:
            self.refresh_services()
        elif index == 2 and not self.has_startup:
            self.refresh_startup()
        elif index == 3 and not self.system_text.toPlainText():
            self.refresh_system()

    def refresh_current(self):
        if self.tasks:
            return
        index = self.tabs.currentIndex()
        if index == 1:
            self.refresh_services()
        elif index == 2:
            self.refresh_startup()
        elif index == 3:
            self.refresh_system()

    def selected(self, table, model):
        indices = table.selectionModel().selectedRows()
        if not indices:
            self.statusBar().showMessage("Сначала выберите строку.", 4000)
            return None
        source = table.model().mapToSource(indices[0])
        return model.rows[source.row()]

    def on_snapshot(self, snapshot):
        parents = {row.pid: row for row in snapshot.processes}
        decorated = []
        for row in snapshot.processes:
            signature = self.signature_results.get(row.exe)
            parts = [path_findings(row.name, row.exe, os.environ.get('SystemRoot', r'C:\Windows')),
                     parent_findings(row, parents)]
            if signature:
                parts.append(signature.status + (' · ' + signature.publisher if signature.publisher else ''))
            decorated.append(replace(row, findings='; '.join(part for part in parts if part)))
        snapshot = replace(snapshot, processes=tuple(decorated))
        self.last_snapshot = snapshot
        if self.signature_worker.enabled and time.monotonic() - self.signature_enqueue_time >= 60:
            self.signature_worker.enqueue({row.exe for row in snapshot.processes if row.exe})
            self.signature_enqueue_time = time.monotonic()
        # Persistent indices invalidate indices. Restore selection by PID AND creation time, never row number.
        selected = self.selected_process_silent()
        scroll = self.process_table.verticalScrollBar().value()
        self.process_model.replace(snapshot.processes)
        now = time.monotonic()
        if now - self.last_sort_time >= 5:
            self.process_proxy.invalidate()
            self.last_sort_time = now
        if selected and self.selected_process_silent() != selected:
            for row, process in enumerate(self.process_model.rows):
                if (process.pid, process.created) == selected:
                    proxy_index = self.process_proxy.mapFromSource(self.process_model.index(row, 0))
                    if proxy_index.isValid():
                        self.process_table.selectRow(proxy_index.row())
                    break
        self.process_table.verticalScrollBar().setValue(scroll)
        self.cpu_card.update_value(f"{snapshot.cpu:.1f}%", f"Процессов: {len(snapshot.processes)}", snapshot.cpu)
        self.memory_card.update_value(f"{snapshot.memory_percent:.1f}%",
                                      f"{human_bytes(snapshot.memory_used)} / {human_bytes(snapshot.memory_total)}",
                                      snapshot.memory_percent)
        self.net_card.update_value(human_bytes(snapshot.net_recv) + "/с",
                                   "Передача: " + human_bytes(snapshot.net_sent) + "/с", snapshot.net_recv)
        self.disk_card.update_value(human_bytes(snapshot.disk_read) + "/с",
                                    "Запись: " + human_bytes(snapshot.disk_write) + "/с", snapshot.disk_read)
        stamp = time.strftime("%H:%M:%S", time.localtime(snapshot.sampled_at))
        self.statusBar().showMessage(f"Обновлено {stamp}  ·  Процессов {len(snapshot.processes)}  ·  "
                                     f"Сбор: {snapshot.collection_ms:.0f} мс  ·  Недоступно: {snapshot.errors}  ·  ЦП: доля всей системы")

    def selected_process_silent(self):
        indices = self.process_table.selectionModel().selectedRows()
        if indices:
            source = self.process_proxy.mapToSource(indices[0])
            p = self.process_model.rows[source.row()]
            return p.pid, p.created
        return None

    def run_task(self, fn, callback=None, on_error=None):
        task = Task(fn)
        self.tasks.add(task)
        self.set_busy(True)
        if callback:
            task.signals.result.connect(callback)
        task.signals.error.connect(on_error or self.report_error)
        task.signals.finished.connect(partial(self.task_finished, task))
        self.pool.start(task)

    def task_finished(self, task):
        self.tasks.discard(task)
        self.set_busy(bool(self.tasks))

    def set_busy(self, busy):
        for button in self.action_buttons:
            button.setEnabled(not busy)

    def report_error(self, text):
        self.log("ОШИБКА: " + text)
        QMessageBox.warning(self, "Операция не выполнена", text + "\n\nЕсли доступ запрещён, попробуйте запуск от администратора. "
                            "Некоторые защищённые процессы недоступны даже с повышенными правами.")

    def log(self, text):
        stamp = time.strftime("%H:%M:%S")
        self.log_text.appendPlainText(f"[{stamp}] {text}")
        logging.getLogger("opentask").info(text)
        self.statusBar().showMessage(text.replace("\n", " ")[:220], 8000)

    def confirm(self, title, text):
        return QMessageBox.question(self, title, text,
                                    QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                                    QMessageBox.StandardButton.No) == QMessageBox.StandardButton.Yes

    def mutate_process(self, action):
        if self.tasks:
            return
        p = self.selected(self.process_table, self.process_model)
        if p is None:
            return
        descriptions = {
            "terminate": "Принудительно завершить? В Windows это НЕ мягкое закрытие окна. Несохранённые данные будут потеряны.",
            "suspend": "Приостановить все потоки? Программа перестанет отвечать и может удерживать ресурсы до возобновления.",
            "resume": "Возобновить потоки процесса?",
        }
        warning = descriptions.get(action, "Изменить приоритет? Это может ухудшить отзывчивость системы.")
        if self.confirm("Подтверждение", f"{p.name} · PID {p.pid}\n\n{warning}"):
            self.run_task(partial(process_action, p.pid, p.created, action), self.log)

    def priority_menu(self):
        if self.tasks:
            return
        menu = QMenu(self)
        for text, action in [("Низкий", "idle"), ("Ниже обычного", "below"), ("Обычный", "normal"),
                             ("Выше обычного", "above"), ("Высокий", "high")]:
            menu.addAction(text, partial(self.mutate_process, action))
        menu.exec(self.cursor().pos())

    def process_menu(self, position):
        if self.tasks:
            return
        index = self.process_table.indexAt(position)
        if not index.isValid():
            return
        self.process_table.selectRow(index.row())
        menu = QMenu(self)
        menu.addAction("Анализ: дерево / подпись / VT / DLL / сеть / handles…", self.inspect_process)
        menu.addAction("Свойства", self.show_details)
        menu.addAction("Открыть расположение", self.open_file)
        menu.addSeparator()
        menu.addAction("Завершить…", partial(self.mutate_process, "terminate"))
        menu.addAction("Завершить дерево…", self.kill_selected_tree)
        menu.exec(self.process_table.viewport().mapToGlobal(position))

    def show_details(self, *_):
        if self.tasks:
            return
        p = self.selected(self.process_table, self.process_model)
        if p:
            self.run_task(partial(process_details, p.pid, p.created), self.details_dialog)

    def details_dialog(self, details):
        dialog = QDialog(self)
        dialog.setWindowTitle("Свойства процесса — снимок")
        dialog.resize(780, 510)
        layout = QVBoxLayout(dialog)
        text = QPlainTextEdit()
        text.setReadOnly(True)
        text.setPlainText("\n\n".join(f"{key}:\n{value}" for key, value in details.items()))
        layout.addWidget(text)
        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Close)
        buttons.rejected.connect(dialog.reject)
        copy = buttons.addButton("Копировать всё", QDialogButtonBox.ButtonRole.ActionRole)
        copy.clicked.connect(lambda: QApplication.clipboard().setText(text.toPlainText()))
        layout.addWidget(buttons)
        # Non-modal open: pending worker finished signal must be processed normally.
        dialog.setAttribute(Qt.WidgetAttribute.WA_DeleteOnClose)
        dialog.open()

    def open_file(self):
        if self.tasks:
            return
        p = self.selected(self.process_table, self.process_model)
        if p:
            self.run_task(partial(show_process_file, p.pid, p.created), self.log)

    def refresh_services(self):
        self.run_task(list_services, self.services_loaded)

    def services_loaded(self, rows):
        self.service_model.replace(rows)
        self.has_services = True
        self.log(f"Список служб обновлён: {len(rows)}.")

    def mutate_service(self, action):
        if self.tasks:
            return
        service = self.selected(self.service_table, self.service_model)
        if service is None:
            return
        name = service["name"]
        text = f"{'Остановить' if action == 'stop' else 'Запустить'} службу {name}?"
        if action == "stop":
            text += "\n\nЭто может нарушить работу Windows, сети или других программ. Зависимые службы не останавливаются автоматически."
        if self.confirm("Управление службой", text):
            self.run_task(partial(service_action, name, action), self.service_done)

    def service_done(self, output):
        self.log(output)
        self.refresh_services()
        # SCM may still report start_pending / stop_pending. Do not claim completion.
        QTimer.singleShot(2000, self.delayed_service_refresh)

    def delayed_service_refresh(self):
        if not self.tasks and self.tabs.currentIndex() == 1:
            self.refresh_services()

    def startup_manager(self):
        return StartupManager(WinRegistry(), BackupStore(self.data_dir / "startup-backup.json"))

    def refresh_startup(self):
        self.run_task(lambda: self.startup_manager().entries() + folder_entries(), self.startup_loaded)

    def startup_loaded(self, rows):
        self.startup_model.replace(rows)
        self.has_startup = True
        self.log(f"Список автозагрузки обновлён: {len(rows)}.")

    def copy_startup(self):
        entry = self.selected(self.startup_table, self.startup_model)
        if entry:
            QApplication.clipboard().setText(entry.command)
            self.log("Команда скопирована. Ничего не запускалось.")

    def toggle_startup(self):
        if self.tasks:
            return
        entry = self.selected(self.startup_table, self.startup_model)
        if entry is None:
            return
        if not entry.editable:
            self.report_error("Элемент из папки Startup доступен только для просмотра.")
            return
        action = "Отключить" if entry.enabled else "Включить"
        text = f"{action} {entry.name} ({entry.location})?\n\n"
        text += "Будет изменена только запись Run. Уже запущенная программа не закрывается.\n"
        text += "Не удаляйте %LOCALAPPDATA%\\OpenTaskMonitor: там хранятся копии отключённых записей."
        if self.confirm("Автозагрузка", text):
            self.run_task(lambda: self.startup_manager().toggle(entry), self.startup_done)

    def startup_done(self, message):
        self.log(message)
        self.refresh_startup()

    def refresh_system(self):
        self.run_task(system_info, self.system_text.setPlainText)

    def export_csv(self):
        if not self.last_snapshot:
            return
        rows = [self.process_model.rows[self.process_proxy.mapToSource(self.process_proxy.index(i, 0)).row()]
                for i in range(self.process_proxy.rowCount())]
        path, _ = QFileDialog.getSaveFileName(self, "Экспорт снимка процессов", "processes.csv", "CSV (*.csv)")
        if path:
            try:
                Path(path).write_text(processes_csv(rows), encoding="utf-8-sig")
                self.log(f"Экспортировано {len(rows)} процессов: {path}")
            except OSError as exc:
                self.report_error(str(exc))

    def about(self):
        QMessageBox.about(self, "OpenTask Monitor", f"OpenTask Monitor {__version__}\n\n"
                          "Независимый open-source диспетчер для Windows 10/11.\nЛицензия: MIT. Python · PySide6 · psutil.\n\n"
                          "Не связан с AnVir и не использует его код или оформление.\n"
                          "Не является антивирусом и не оценивает безопасность процессов.\n"
                          "VirusTotal — только вручную, hash-only; телеметрии и обновлений нет.\n\n"
                          "F5 — обновление служб/автозагрузки/системы\nCtrl+F — поиск · Ctrl+S — CSV")

    def change_launch_mode(self, enabled):
        try:
            set_random_enabled(self.data_dir, enabled)
        except OSError as exc:
            self.random_launch_action.blockSignals(True)
            self.random_launch_action.setChecked(random_enabled(self.data_dir))
            self.random_launch_action.blockSignals(False)
            self.report_error('Не удалось сохранить режим запуска: ' + str(exc))
            return
        self.log('Следующий запуск OpenTaskMonitor.exe: ' +
                 ('случайное имя процесса/окна.' if enabled else 'обычный режим.'))

    def open_licenses(self):
        from PySide6.QtCore import QUrl
        from PySide6.QtGui import QDesktopServices
        package = os.environ.get('OPENTASK_PACKAGE_DIR')
        if package:
            directory = Path(package)
        elif Path(sys.executable).parent.name.casefold() == 'runtime':
            directory = Path(sys.executable).parent.parent
        else:
            directory = Path(__file__).resolve().parents[3]
        if not QDesktopServices.openUrl(QUrl.fromLocalFile(str(directory))):
            QMessageBox.information(self, 'Лицензии и сборка', str(directory))

    def launch_mode_help(self):
        QMessageBox.information(self, 'Одна программа — два режима',
            'Запускайте только OpenTaskMonitor.exe.\n\n'
            'Поставьте или снимите флажок «Запуск → Случайное имя при следующем запуске», '
            'закройте программу и откройте тот же EXE заново. Текущий процесс не переименовывается.\n\n'
            'В случайном режиме нужна запись в папку runtime. Это не защита от завершения '
            'или вредоносного ПО. В однофайловой сборке runtime автоматически хранится в папке данных; '
            'в старой папочной сборке он должен оставаться рядом с EXE.')

    def signature_enabled(self, enabled):
        self.signature_worker.enabled = enabled
        self.signature_enqueue_time = 0
        if enabled and self.last_snapshot:
            self.signature_worker.enqueue({row.exe for row in self.last_snapshot.processes if row.exe})
            self.signature_enqueue_time = time.monotonic()
        self.log('Фоновые подписи: ' + ('включены; результаты в столбце «Проверка».' if enabled else 'выключены.'))

    def signature_received(self, path, result):
        # Apply batched with the next process snapshot, not a full table update per signature.
        self.signature_results[path] = result

    def inspect_process(self):
        if self.tasks:
            return
        row = self.selected(self.process_table, self.process_model)
        if row:
            Inspector(self, row).show()

    def forget_vt_key(self):
        self.vt_key = ''
        self.log('API-ключ VirusTotal удалён из текущего сеанса (на диск он не записывался).')

    def kill_selected_tree(self):
        if self.tasks:
            return
        row = self.selected(self.process_table, self.process_model)
        if row and self.confirm('Завершение дерева',
            f'{row.name} · PID {row.pid}\n\nПринудительно завершить процесс и всех найденных потомков? '
            'Несохранённые данные потеряются. Это снимок, а не атомарное отключение: '
            'новые потомки и внешние watchdog могут перезапустить приложение.'):
            self.run_task(partial(kill_tree, row.pid, row.created), self.log)

    def delete_selected_file(self, reboot=False):
        if self.tasks:
            return
        row = self.selected(self.process_table, self.process_model)
        if row is None:
            return
        title = 'Удалить при перезагрузке' if reboot else 'Завершить и удалить файл'
        warning = ('Файл будет поставлен в очередь удаления Windows. Это не немедленное удаление, '
                   'очередь не отменяется из приложения.' if reboot else
                   'Процесс будет принудительно завершён, EXE удалён БЕЗ КОРЗИНЫ. '
                   'При отказе доступа файл останется, но процесс уже может быть закрыт.')
        if self.confirm(title, f'{row.name} · PID {row.pid}\n{row.exe}\n\n{warning}\n'
                        'Удаление системных файлов Windows и файлов самого диспетчера заблокировано. Продолжить?'):
            self.run_task(partial(remove_file, row.pid, row.created, reboot), self.log)

    def task_inventory(self):
        self.run_task(scheduled_tasks, partial(self.inventory_dialog, 'Планировщик задач — только чтение'))

    def inventory_dialog(self, title, rows):
        dialog = QDialog(self)
        dialog.setWindowTitle(title)
        dialog.resize(1100, 650)
        layout = QVBoxLayout(dialog)
        label = QLabel('Скрытые задачи включены, если доступны текущему пользователю. '
                       'Здесь только просмотр: изменение заданий не реализовано.')
        label.setWordWrap(True)
        layout.addWidget(label)
        headers = list(rows[0]) if rows else ['Список пуст / недоступен']
        model = TableModel(headers, lambda row, col: str(row.get(headers[col], '')), dialog)
        model.replace(rows)
        table, proxy = self.make_table(model)
        proxy.setParent(dialog)
        layout.addWidget(table)
        search = QLineEdit()
        search.setPlaceholderText('Поиск заданий…')
        search.textChanged.connect(proxy.set_query)
        layout.addWidget(search)
        dialog.setAttribute(Qt.WidgetAttribute.WA_DeleteOnClose)
        dialog.open()

    def closeEvent(self, event):
        self.monitor.stop()
        self.signature_worker.stop()
        self.signature_worker.wait(50)
        if self.monitor.isRunning() or self.signature_worker.isRunning() or self.tasks:
            self.statusBar().showMessage("Ожидание завершения фоновых операций перед выходом…")
            event.ignore()
            QTimer.singleShot(300, self.close)
            return
        self.settings.setValue("geometry", self.saveGeometry())
        self.settings.sync()
        event.accept()
