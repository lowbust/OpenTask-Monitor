from __future__ import annotations

import json
from functools import partial

from PySide6.QtCore import Qt, QTimer
from PySide6.QtWidgets import (
    QCheckBox,
    QDialog,
    QHBoxLayout,
    QInputDialog,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPlainTextEdit,
    QPushButton,
    QTabWidget,
    QTreeWidget,
    QTreeWidgetItem,
    QVBoxLayout,
    QWidget,
)

from opentask import inspection
from opentask.backend import checked_process
from opentask.signatures import verify_signature
from opentask.ui.models import SearchProxy, TableModel


def tree_relationships(rows):
    """Use only older parents; a recycled parent PID must not manufacture ancestry."""
    lookup = {row.pid: row for row in rows}
    return {row.pid: row.ppid if row.ppid in lookup and lookup[row.ppid].created <= row.created
            and row.ppid != row.pid else None for row in rows}


class Inspector(QDialog):
    def __init__(self, owner, row):
        super().__init__(owner)
        self.owner, self.row = owner, row
        self.busy, self.want_close = False, False
        self.buttons = []
        self.setWindowTitle(f'Анализ: {row.name} · PID {row.pid}')
        self.resize(1080, 720)
        self.setAttribute(Qt.WidgetAttribute.WA_DeleteOnClose)
        layout = QVBoxLayout(self)
        notice = QLabel('Проверки по запросу. Доступ может требовать администратора. '
                        'Ни подпись, ни VirusTotal, ни эвристика пути не гарантируют безопасность.')
        notice.setWordWrap(True)
        layout.addWidget(notice)
        self.tabs = QTabWidget()
        layout.addWidget(self.tabs)
        self.security_text = QPlainTextEdit()
        self.security_text.setReadOnly(True)
        page, buttons = self.page(self.security_text)
        self.add_button(buttons, 'Цифровая подпись (offline)', self.signature)
        self.add_button(buttons, 'SHA-256 / VirusTotal…', self.virustotal)
        self.tabs.addTab(page, 'Подпись / VirusTotal')
        self.tree = QTreeWidget()
        self.tree.setHeaderLabels(['Процесс', 'PID', 'Родитель', 'Путь / замечания'])
        self.tree.setColumnWidth(0, 260)
        self.tree.setColumnWidth(1, 70)
        page, buttons = self.page(self.tree)
        self.add_button(buttons, 'Обновить дерево (снимок)', self.populate_tree)
        self.tabs.addTab(page, 'Process Tree')
        self.dll_table, self.dll_model = self.table(['Путь', 'RSS'])
        page, buttons = self.page(self.dll_table)
        self.add_button(buttons, 'Загрузить DLL', self.load_dlls)
        self.tabs.addTab(page, 'DLL')
        self.net_table, self.net_model = self.table(['Протокол', 'Семейство', 'Локальный IP', 'Порт',
                                                   'Удалённый IP', 'Удалённый порт', 'Состояние'])
        page, buttons = self.page(self.net_table)
        self.add_button(buttons, 'Обновить соединения', self.load_connections)
        self.auto_net = QCheckBox('Каждые 3 с (только эта вкладка)')
        buttons.addWidget(self.auto_net)
        self.add_button(buttons, 'Разорвать IPv4 TCP…', self.disconnect)
        self.tabs.addTab(page, 'Сеть')
        self.handle_table, self.handle_model = self.table(['Handle', 'Тип', 'Имя NT', 'Access'])
        page, buttons = self.page(self.handle_table)
        self.add_button(buttons, 'Файлы и ключи реестра (до 10 с)', self.load_handles)
        self.tabs.addTab(page, 'Дескрипторы')
        self.status = QLabel('Выберите проверку. Подпись и VT относятся к файлу на диске, не к памяти процесса.')
        self.status.setWordWrap(True)
        layout.addWidget(self.status)
        self.timer = QTimer(self)
        self.timer.setInterval(3000)
        self.timer.timeout.connect(self.auto_refresh)
        self.timer.start()
        self.populate_tree()

    def page(self, content):
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.addWidget(content)
        buttons = QHBoxLayout()
        layout.addLayout(buttons)
        return page, buttons

    def add_button(self, layout, text, callback):
        button = QPushButton(text)
        button.clicked.connect(callback)
        self.buttons.append(button)
        layout.addWidget(button)

    def table(self, headers):
        model = TableModel(headers, lambda row, col: row.get(headers[col], ''), self)
        table, proxy = self.owner.make_table(model)
        table.setColumnWidth(0, 250)
        # Proxy is QObject-owned by the main window, table by this dialog.
        if isinstance(proxy, SearchProxy):
            proxy.setParent(self)
        return table, model

    def run(self, function, callback):
        if self.busy:
            return
        self.busy = True
        self.status.setText('Выполняется в фоне…')
        for button in self.buttons:
            button.setEnabled(False)
        self.owner.run_task(function, partial(self.task_done, callback), self.failed)

    def release(self):
        self.busy = False
        for button in self.buttons:
            button.setEnabled(True)
        if self.want_close:
            self.close()

    def task_done(self, callback, result):
        if not self.want_close:
            callback(result)
            self.status.setText('Готово. Данные — снимок; могут измениться сразу после чтения.')
        self.release()

    def failed(self, error):
        self.status.setText(error)
        self.release()

    def current_file(self):
        return checked_process(self.row.pid, self.row.created).exe()

    def signature(self):
        def work():
            path = self.current_file()
            result = verify_signature(path)
            return {'Файл': path, 'Результат': result.status, 'Издатель': result.publisher,
                    'Windows code': f'0x{result.code:08X}',
                    'Примечание': 'Offline WinVerifyTrust + каталоги. Отзыв сертификата онлайн не проверялся. '
                                   'Доверенная подпись не означает, что программа безопасна.'}
        self.run(work, lambda result: self.security_text.setPlainText(json.dumps(result, ensure_ascii=False, indent=2)))

    def virustotal(self):
        if not self.owner.confirm('VirusTotal: отправка хеша',
            'Будет отправлен SHA-256 выбранного EXE на virustotal.com с вашим API-ключом. '
            'Сам файл, имя и командная строка не загружаются. Запрос раскрывает VT интерес к этому хешу. Продолжить?'):
            return
        key = getattr(self.owner, 'vt_key', '')
        if not key:
            key, accepted = QInputDialog.getText(self, 'VirusTotal API v3',
                'Личный API-ключ (только в памяти текущего сеанса):', QLineEdit.EchoMode.Password)
            if not accepted or not key.strip():
                return
            self.owner.vt_key = key.strip()
        try:
            self.owner.vt_limit.acquire()
        except Exception as exc:
            self.failed(str(exc))
            return
        self.run(lambda: inspection.virustotal(self.current_file(), self.owner.vt_key),
                 lambda result: self.security_text.setPlainText(json.dumps(result, ensure_ascii=False, indent=2)))

    def populate_tree(self):
        if not self.owner.last_snapshot:
            return
        rows = self.owner.last_snapshot.processes
        parents = tree_relationships(rows)
        lookup = {row.pid: row for row in rows}
        nodes = {row.pid: QTreeWidgetItem([row.name, str(row.pid), str(row.ppid),
                                          row.exe + (' | ' + row.findings if row.findings else '')]) for row in rows}
        self.tree.clear()
        for row in rows:
            parent = parents[row.pid]
            # Guard cycles even in synthetic/corrupt input.
            visited = {row.pid}
            cursor = parent
            while cursor is not None and cursor not in visited:
                visited.add(cursor)
                cursor = parents.get(cursor)
            if parent is not None and cursor is None:
                nodes[parent].addChild(nodes[row.pid])
            else:
                self.tree.addTopLevelItem(nodes[row.pid])
            if row.pid == self.row.pid:
                nodes[row.pid].setSelected(True)
                ancestor = parent
                seen = set()
                while ancestor is not None and ancestor not in seen:
                    seen.add(ancestor)
                    nodes[ancestor].setExpanded(True)
                    ancestor = parents.get(ancestor)
        node = nodes.get(self.row.pid)
        if node:
            self.tree.scrollToItem(node)
        # Shell/parent alerts are hints; for example an IDE legitimately starts PowerShell.
        _ = lookup

    def load_dlls(self):
        self.run(partial(inspection.dlls, self.row.pid, self.row.created), self.dll_model.replace)

    def load_connections(self):
        self.run(partial(inspection.connections, self.row.pid, self.row.created), self.net_model.replace)

    def auto_refresh(self):
        if self.isVisible() and self.auto_net.isChecked() and self.tabs.currentIndex() == 3 and not self.busy:
            self.load_connections()

    def disconnect(self):
        row = self.owner.selected(self.net_table, self.net_model)
        if row and self.owner.confirm('Разрыв TCP', 'Разорвать выбранное IPv4 TCP-соединение? '
            'Может требоваться администратор. Передача данных оборвётся, процесс может переподключиться.'):
            self.run(partial(inspection.disconnect, self.row.pid, self.row.created, row),
                     lambda result: QMessageBox.information(self, 'Сеть', result))

    def load_handles(self):
        def loaded(result):
            self.handle_model.replace(result['rows'])
            QMessageBox.information(self, 'Ограничения дескрипторов', result['note'])
        self.run(partial(inspection.handles, self.row.pid, self.row.created), loaded)

    def closeEvent(self, event):
        self.timer.stop()
        if self.busy:
            self.want_close = True
            self.hide()
            event.ignore()
        else:
            event.accept()
