from __future__ import annotations

import json
import time
from functools import partial
from pathlib import Path

from PySide6.QtCore import Qt, QTimer, QUrl
from PySide6.QtGui import QDesktopServices
from PySide6.QtWidgets import (
    QCheckBox,
    QComboBox,
    QDialog,
    QFileDialog,
    QHBoxLayout,
    QLabel,
    QPlainTextEdit,
    QPushButton,
    QTabWidget,
    QVBoxLayout,
    QWidget,
)

from opentask import event_audit, snapshots, system_watch
from opentask.forensics import gpu_telemetry
from opentask.ui.models import TableModel
from opentask.ui.widgets import MetricCard


class DefenseCenter(QDialog):
    def __init__(self, owner):
        super().__init__(owner)
        self.owner = owner
        self.busy = self.want_close = False
        self.watch_state = None
        self.events = []
        self.previous_gpu = None
        self.last_gpu = self.last_audit = 0
        self.setWindowTitle('Система: снимки, аудит и наблюдение — без kernel-защиты')
        self.resize(1180, 800)
        self.setAttribute(Qt.WidgetAttribute.WA_DeleteOnClose)
        root = QVBoxLayout(self)
        note = QLabel('Read-only наблюдение ≠ блокировка. Снимки, датчики и журналы не подтверждают отсутствие malware. '
                      'Автопроверки выключены до явного включения, чтобы не нагружать список процессов.')
        note.setWordWrap(True)
        root.addWidget(note)
        self.tabs = QTabWidget()
        root.addWidget(self.tabs, 1)
        self.build_snapshot()
        self.build_watch()
        self.build_audit()
        self.build_hardware()
        self.build_quarantine()
        self.status = QLabel('Готово. Клавиши/буфер обмена не перехватываются и не записываются.')
        self.status.setWordWrap(True)
        root.addWidget(self.status)
        self.timer = QTimer(self)
        self.timer.setInterval(2000)
        self.timer.timeout.connect(self.tick)
        self.timer.start()

    def page(self):
        page = QWidget()
        layout = QVBoxLayout(page)
        buttons = QHBoxLayout()
        layout.addLayout(buttons)
        return page, layout, buttons

    def button(self, layout, text, callback):
        button = QPushButton(text)
        button.clicked.connect(callback)
        layout.addWidget(button)
        return button

    def table(self, headers, layout):
        model = TableModel(headers, lambda row, column: str(row.get(headers[column], '')), self)
        table, proxy = self.owner.make_table(model)
        proxy.setParent(self)
        table.setColumnWidth(0, 180)
        layout.addWidget(table, 1)
        return model, table

    def run(self, work, callback):
        if self.busy:
            return
        self.busy = True
        self.status.setText('Чтение в фоне…')
        self.owner.run_task(work, partial(self.task_done, callback), self.failed, block_actions=False)

    def task_done(self, callback, result):
        if not self.want_close:
            try:
                callback(result)
                self.status.setText('Обновлено ' + time.strftime('%H:%M:%S') + '. Данные — снимок, не гарантия безопасности.')
            except Exception as exc:
                self.status.setText(str(exc))
        self.release()

    def failed(self, error):
        self.status.setText(error)
        self.release()

    def release(self):
        self.busy = False
        if self.want_close:
            self.close()

    def build_snapshot(self):
        page, layout, buttons = self.page()
        self.tasks_check = QCheckBox('Включить задания (PowerShell, может занять до 35 с)')
        layout.addWidget(self.tasks_check)
        self.button(buttons, 'Сохранить текущий эталон…', self.capture_baseline)
        self.button(buttons, 'Загрузить эталон…', self.load_baseline)
        self.button(buttons, 'Сравнить с текущей системой', self.compare_baseline)
        self.new_only = QCheckBox('Только новые EXE в основной таблице')
        self.new_only.setEnabled(self.owner.baseline is not None)
        self.new_only.setChecked(self.owner.new_only_action.isChecked())
        self.new_only.toggled.connect(self.owner.new_only_action.setChecked)
        self.owner.new_only_action.toggled.connect(self.new_only.setChecked)
        layout.addWidget(self.new_only)
        note = QLabel('Новые процессы сравниваются по EXE + имени + пользователю, не по PID. '
                      'Перезапуск того же EXE не считается новым. Подмена в памяти/замена файла по тому же пути '
                      'этим сравнением не выявляется. «Чистота» эталона не подтверждается приложением.')
        note.setWordWrap(True)
        layout.addWidget(note)
        self.diff_model, _ = self.table(['Раздел', 'Изменение', 'Элемент', 'Данные'], layout)
        self.tabs.addTab(page, 'Снимки / новые элементы')

    def current_capture(self, include_tasks):
        rows = self.owner.last_snapshot.processes if self.owner.last_snapshot else ()
        return partial(snapshots.capture, rows, self.owner.data_dir, include_tasks)

    def capture_baseline(self):
        if self.busy:
            return
        filename, _ = QFileDialog.getSaveFileName(self, 'Эталон JSON', 'opentask-baseline.json', 'JSON (*.json)')
        if not filename:
            return
        capture = self.current_capture(self.tasks_check.isChecked())
        def work():
            value = capture()
            snapshots.atomic_json(Path(filename), value)
            return value
        self.run(work, self.baseline_ready)

    def load_baseline(self):
        if self.busy:
            return
        filename, _ = QFileDialog.getOpenFileName(self, 'Загрузить эталон', '', 'JSON (*.json)')
        if filename:
            self.run(partial(snapshots.load, Path(filename)), self.baseline_ready)

    def baseline_ready(self, value):
        self.owner.set_baseline(value)
        self.new_only.setEnabled(True)
        self.diff_model.replace([{'Раздел': 'baseline', 'Изменение': 'Загружен',
                                  'Элемент': str(len(value.get('processes', []))) + ' процессов',
                                  'Данные': json.dumps(value.get('errors', []), ensure_ascii=False)}])

    def compare_baseline(self):
        if self.owner.baseline is None:
            self.status.setText('Сначала сохраните или загрузите эталон.')
            return
        baseline = self.owner.baseline
        self.run(self.current_capture(self.tasks_check.isChecked()),
                 lambda current: self.diff_model.replace(snapshots.compare(baseline, current)))

    def build_watch(self):
        page, layout, buttons = self.page()
        self.watch_check = QCheckBox('Наблюдать hosts / DNS / IFEO каждые 2 секунды')
        layout.addWidget(self.watch_check)
        self.button(buttons, 'Прочитать текущее состояние', self.read_watch)
        self.button(buttons, 'Сохранить состояние JSON…', self.save_watch)
        note = QLabel('Изменения обнаруживаются опросом, НЕ предотвращаются. Автор изменения не устанавливается. '
                      'DNS может менять DHCP/VPN; DoH/NRPT не охвачены. IFEO — только фиксированные имена/значения, Debugger может быть легитимным. '
                      'Автоматического удаления Debugger/защиты записи нет; отчёт сохраняется для анализа.')
        note.setWordWrap(True)
        layout.addWidget(note)
        self.watch_model, _ = self.table(['Время', 'Область', 'Событие', 'До', 'После', 'Примечание'], layout)
        self.watch_text = QPlainTextEdit()
        self.watch_text.setReadOnly(True)
        self.watch_text.setMaximumHeight(200)
        layout.addWidget(self.watch_text)
        self.tabs.addTab(page, 'hosts / DNS / IFEO')

    def read_watch(self):
        self.run(system_watch.read_state, self.watch_ready)

    def watch_ready(self, value):
        for event in system_watch.changes(self.watch_state, value):
            event['Время'] = time.strftime('%H:%M:%S')
            self.events.append(event)
        self.events = self.events[-500:]
        self.watch_model.replace(self.events)
        self.watch_state = value
        self.watch_text.setPlainText(json.dumps(value, ensure_ascii=False, indent=2))

    def save_watch(self):
        if self.watch_state is None:
            self.status.setText('Сначала прочитайте состояние.')
            return
        filename, _ = QFileDialog.getSaveFileName(self, 'Состояние hosts/DNS/IFEO', 'system-watch.json', 'JSON (*.json)')
        if filename:
            self.run(partial(snapshots.atomic_json, Path(filename), self.watch_state), lambda _: None)

    def build_audit(self):
        page, layout, buttons = self.page()
        self.audit_channel = QComboBox()
        self.audit_channel.addItems([event_audit.SYSMON, 'Security'])
        buttons.addWidget(self.audit_channel)
        self.button(buttons, 'События за 10 минут (до 200)', self.read_audit)
        self.audit_check = QCheckBox('Обновлять каждые 10 с на этой вкладке')
        layout.addWidget(self.audit_check)
        note = QLabel('Это существующие журналы, НЕ перехват WinAPI. Sysmon должен быть отдельно установлен '
                      'и настроен администратором; Security audit тоже может быть выключен. '
                      'Event 10 означает доступ к процессу, не факт вызова WriteProcessMemory. '
                      'WH_KEYBOARD_LL / GetAsyncKeyState и чтение clipboard надёжно не перечисляются: '
                      'кейлоггер-детектор не заявляется, нажатия и буфер не записываются.')
        note.setWordWrap(True)
        layout.addWidget(note)
        self.audit_model, _ = self.table(['Время UTC', 'Канал', 'Record', 'ID', 'Событие', 'Замечание', 'Данные'], layout)
        self.tabs.addTab(page, 'Windows / Sysmon audit')

    def read_audit(self):
        channel = self.audit_channel.currentText()
        self.last_audit = time.monotonic()
        self.run(partial(event_audit.read_events, channel), self.audit_model.replace)

    def build_hardware(self):
        page, layout, buttons = self.page()
        self.button(buttons, 'Прочитать NVIDIA NVML', self.read_gpu)
        self.gpu_check = QCheckBox('Каждые 5 с на этой вкладке')
        buttons.addWidget(self.gpu_check)
        cards = QHBoxLayout()
        self.gpu_load = MetricCard('GPU, %', '#79b8ff')
        self.gpu_temp = MetricCard('GPU, °C', '#ffbf79')
        self.gpu_power = MetricCard('GPU, Вт', '#63ddbc')
        for card in (self.gpu_load, self.gpu_temp, self.gpu_power):
            cards.addWidget(card)
        layout.addLayout(cards)
        self.hardware_text = QPlainTextEdit()
        self.hardware_text.setReadOnly(True)
        layout.addWidget(self.hardware_text)
        note = QLabel('Реальные датчики только если NVML/драйвер их поддерживают. CPU/AMD/Intel power/temp '
                      'без аппаратного провайдера недоступны и не заменяются нулями. '
                      'Инерция температуры и снижение нагрузки обычны; графики не детектор майнера.')
        note.setWordWrap(True)
        layout.addWidget(note)
        self.tabs.addTab(page, 'GPU: температура / энергия')

    def read_gpu(self):
        self.last_gpu = time.monotonic()
        self.run(gpu_telemetry, self.gpu_ready)

    def gpu_ready(self, result):
        gpu = result['devices'][0] if result['devices'] else {}
        text = time.strftime('Снимок %H:%M:%S\n') + json.dumps(result, ensure_ascii=False, indent=2)
        previous = self.previous_gpu
        if previous and gpu and previous.get('name') == gpu.get('name'):
            fields = ('gpu_percent', 'temperature_C')
            if all(previous.get(field) is not None and gpu.get(field) is not None for field in fields):
                if previous['gpu_percent'] >= 60 and previous['gpu_percent'] - gpu['gpu_percent'] >= 40:
                    if gpu['temperature_C'] >= previous['temperature_C'] - 2:
                        text += ('\n\nНаблюдение: нагрузка GPU упала ≥40 п.п., температура почти не снизилась. '
                                 'Обычно это тепловая инерция, НЕ доказательство скрытого майнинга. '
                                 'Процессы GPU здесь не атрибутируются; баллы за это не начисляются.')
        self.hardware_text.setPlainText(text)
        for field, card, suffix in [('gpu_percent', self.gpu_load, '%'), ('temperature_C', self.gpu_temp, '°C'),
                                    ('power_W', self.gpu_power, ' Вт')]:
            value = gpu.get(field)
            if value is not None:
                card.update_value(f'{value:.1f}{suffix}', gpu['name'], value)
            else:
                card.value, card.subtitle = 'н/д', 'Датчик недоступен, не нулевое значение'
                card.update()
        self.previous_gpu = gpu or None

    def build_quarantine(self):
        page, layout, buttons = self.page()
        self.button(buttons, 'Открыть папку контейнеров', self.open_quarantine)
        self.button(buttons, 'Перечитать список', self.list_quarantine)
        note = QLabel('Карантин .vir — ZIP-контейнер с sample.bin и metadata.json, не сырой PE и не sandbox/VM. '
                      'Архив не запускается автоматически, но его можно извлечь и выполнить — не делайте этого '
                      'на рабочей системе. Автоматического восстановления/запуска нет. '
                      'Перемещение: выберите процесс → Инструменты → Карантин. Контейнер сначала проверяется, '
                      'только затем процесс завершается и EXE удаляется обычными правами Windows.')
        note.setWordWrap(True)
        layout.addWidget(note)
        self.quarantine_text = QPlainTextEdit()
        self.quarantine_text.setReadOnly(True)
        layout.addWidget(self.quarantine_text)
        self.tabs.addTab(page, 'Карантин (не sandbox)')
        self.list_quarantine()

    def list_quarantine(self):
        folder = self.owner.data_dir / 'quarantine'
        self.quarantine_text.setPlainText('\n'.join(str(path) for path in sorted(folder.glob('*.vir'))) or 'Контейнеров пока нет.')

    def open_quarantine(self):
        folder = self.owner.data_dir / 'quarantine'
        folder.mkdir(parents=True, exist_ok=True)
        QDesktopServices.openUrl(QUrl.fromLocalFile(str(folder)))

    def tick(self):
        if self.busy or not self.isVisible():
            return
        now = time.monotonic()
        if self.tabs.currentIndex() == 2 and self.audit_check.isChecked() and now - self.last_audit >= 10:
            self.read_audit()
        elif self.tabs.currentIndex() == 3 and self.gpu_check.isChecked() and now - self.last_gpu >= 5:
            self.read_gpu()
        elif self.watch_check.isChecked():
            self.read_watch()

    def closeEvent(self, event):
        self.timer.stop()
        if self.busy:
            self.want_close = True
            self.hide()
            event.ignore()
        else:
            event.accept()
