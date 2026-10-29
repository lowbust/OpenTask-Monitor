from __future__ import annotations

from PySide6.QtCore import QAbstractTableModel, QModelIndex, QSortFilterProxyModel, Qt
from PySide6.QtGui import QColor

from opentask.core import ProcessRow, human_bytes
from opentask.snapshots import process_key

SORT_ROLE = Qt.ItemDataRole.UserRole + 1


class TableModel(QAbstractTableModel):
    def __init__(self, headers, getter, parent=None):
        super().__init__(parent)
        self.headers = headers
        self.getter = getter
        self.rows = []

    def replace(self, rows):
        self.beginResetModel()
        self.rows = list(rows)
        self.endResetModel()

    def rowCount(self, parent=QModelIndex()):
        return 0 if parent.isValid() else len(self.rows)

    def columnCount(self, parent=QModelIndex()):
        return 0 if parent.isValid() else len(self.headers)

    def headerData(self, section, orientation, role=Qt.ItemDataRole.DisplayRole):
        if role == Qt.ItemDataRole.DisplayRole and orientation == Qt.Orientation.Horizontal:
            return self.headers[section]
        return None

    def data(self, index, role=Qt.ItemDataRole.DisplayRole):
        if not index.isValid():
            return None
        if role == Qt.ItemDataRole.ForegroundRole and isinstance(self.rows[index.row()], dict):
            if self.rows[index.row()].get('Замечание'):
                return QColor('#e7cc85')
        value = self.getter(self.rows[index.row()], index.column())
        if role in (Qt.ItemDataRole.DisplayRole, SORT_ROLE):
            return value
        if role == Qt.ItemDataRole.ToolTipRole:
            return str(value)
        return None


class ProcessModel(TableModel):
    def __init__(self, parent=None):
        super().__init__(["Процесс", "PID", "ЦП, %", "Память RSS", "Потоки", "Пользователь", "Статус", "PPID", "Путь", "Проверка", "Приоритет 0–100"],
                         self.value, parent)

    def replace(self, rows):
        """Keep persistent indices: remove/insert only topology changes, never reset."""
        incoming = {(row.pid, row.created): row for row in rows}
        for index in range(len(self.rows) - 1, -1, -1):
            old = self.rows[index]
            if (old.pid, old.created) not in incoming:
                self.beginRemoveRows(QModelIndex(), index, index)
                self.rows.pop(index)
                self.endRemoveRows()
        known = {(row.pid, row.created) for row in self.rows}
        added = [row for key, row in incoming.items() if key not in known]
        if added:
            start = len(self.rows)
            self.beginInsertRows(QModelIndex(), start, start + len(added) - 1)
            self.rows.extend(added)
            self.endInsertRows()
        changed = []
        for index, old in enumerate(self.rows):
            new = incoming[(old.pid, old.created)]
            if old != new:
                self.rows[index] = new
                changed.append(index)
        if changed:
            self.dataChanged.emit(self.index(min(changed), 0),
                                  self.index(max(changed), self.columnCount() - 1), [])

    @staticmethod
    def value(row: ProcessRow, column: int):
        return (row.name, row.pid, row.cpu, row.memory, row.threads, row.username, row.status, row.ppid, row.exe, row.findings, row.triage)[column]

    def data(self, index, role=Qt.ItemDataRole.DisplayRole):
        if not index.isValid():
            return None
        row = self.rows[index.row()]
        col = index.column()
        if role == Qt.ItemDataRole.ToolTipRole and col == 10:
            return row.score_notes or 'Нет начисленных баллов. Это не подтверждение безопасности.'
        if role == Qt.ItemDataRole.ForegroundRole and row.triage >= 60:
            return QColor('#ff8b8b')
        if role == Qt.ItemDataRole.ForegroundRole and col in (0, 9):
            if "нетипичный" in row.findings or "недействительна" in row.findings:
                return QColor("#ffaf83")
            if "не доверена" in row.findings or "не найдена" in row.findings or "проверьте родителя" in row.findings:
                return QColor("#e7cc85")
            if "Microsoft: доверена" in row.findings:
                return QColor("#75d9af")
            if "подпись доверена" in row.findings:
                return QColor("#87b9f0")
        if role == Qt.ItemDataRole.DisplayRole:
            if col == 2:
                return f"{row.cpu:.1f}"
            if col == 3:
                return human_bytes(row.memory)
        if role == Qt.ItemDataRole.TextAlignmentRole and col in (1, 2, 3, 4, 7):
            return int(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)
        if role == Qt.ItemDataRole.ForegroundRole and col == 2 and row.cpu >= 20:
            return QColor("#ffb86b")
        return super().data(index, role)


class SearchProxy(QSortFilterProxyModel):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.query = ""
        self.pin_high = True
        self.new_only = False
        self.baseline_keys = set()
        self.setSortRole(SORT_ROLE)
        self.setSortCaseSensitivity(Qt.CaseSensitivity.CaseInsensitive)
        self.setDynamicSortFilter(True)

    def set_query(self, text):
        if hasattr(self, "beginFilterChange") and hasattr(self, "endFilterChange"):
            self.beginFilterChange()
            self.query = text.strip().casefold()
            self.endFilterChange(QSortFilterProxyModel.Direction.Rows)
        else:  # Qt 6.7 / 6.8 compatibility
            self.query = text.strip().casefold()
            self.invalidateFilter()

    def lessThan(self, left, right):
        model = self.sourceModel()
        if self.pin_high and isinstance(model, ProcessModel):
            first, second = model.rows[left.row()].triage, model.rows[right.row()].triage
            high_first, high_second = first >= 60, second >= 60
            descending = self.sortOrder() == Qt.SortOrder.DescendingOrder
            if high_first != high_second:
                return not high_first if descending else high_first
            if high_first and first != second:
                return first < second if descending else first > second
        return super().lessThan(left, right)

    def filterAcceptsRow(self, row, parent):
        model = self.sourceModel()
        if self.new_only and isinstance(model, ProcessModel) and process_key(model.rows[row]) in self.baseline_keys:
            return False
        if not self.query:
            return True
        model = self.sourceModel()
        haystack = " ".join(str(model.data(model.index(row, col, parent), SORT_ROLE))
                            for col in range(model.columnCount())).casefold()
        return all(token in haystack for token in self.query.split())
