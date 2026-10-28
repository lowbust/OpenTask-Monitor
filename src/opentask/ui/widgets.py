from collections import deque

from PySide6.QtCore import QRectF, Qt
from PySide6.QtGui import QColor, QFont, QPainter, QPainterPath, QPen
from PySide6.QtWidgets import QWidget


class MetricCard(QWidget):
    def __init__(self, title, color, parent=None):
        super().__init__(parent)
        self.title = title
        self.color = QColor(color)
        self.value = "—"
        self.subtitle = "Ожидание данных"
        self.history = deque(maxlen=60)
        self.setMinimumSize(205, 132)
        self.setMaximumHeight(148)

    def update_value(self, value, subtitle, sample):
        self.value, self.subtitle = value, subtitle
        self.history.append(max(0, float(sample)))
        self.update()

    def paintEvent(self, event):
        p = QPainter(self)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        p.setPen(QPen(QColor("#2a394c")))
        p.setBrush(QColor("#182433"))
        p.drawRoundedRect(QRectF(1, 1, self.width() - 2, self.height() - 2), 10, 10)
        p.setPen(QColor("#a2b4cc"))
        p.setFont(QFont("Segoe UI", 10))
        p.drawText(16, 26, self.title)
        p.setPen(self.color)
        p.setFont(QFont("Segoe UI", 22, QFont.Weight.DemiBold))
        p.drawText(16, 60, self.value)
        p.setFont(QFont("Segoe UI", 9))
        p.setPen(QColor("#9cacbf"))
        p.drawText(16, 82, self.subtitle)
        if len(self.history) < 2:
            return
        values = list(self.history)
        maximum = max(100, max(values))
        x0, y0, w, h = 16, self.height() - 16, self.width() - 32, 28
        path = QPainterPath()
        for i, value in enumerate(values):
            x = x0 + w * i / (len(values) - 1)
            y = y0 - (value / maximum) * h
            if i == 0:
                path.moveTo(x, y)
            else:
                path.lineTo(x, y)
        p.setBrush(Qt.BrushStyle.NoBrush)
        p.setPen(QPen(self.color, 1.7))
        p.drawPath(path)
