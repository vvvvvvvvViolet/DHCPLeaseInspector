"""The Diagnose window: pick one machine, run every check, copy the report."""
from PyQt5.QtCore import QThread, pyqtSignal
from PyQt5.QtGui import QColor
from PyQt5.QtWidgets import (
    QApplication,
    QDialog,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
)

from . import diagnose

HEADERS = ["Step", "Result", "Time", "Details"]
_COLOR_OK = QColor("#c8e6c9")
_COLOR_FAIL = QColor("#ffcdd2")
_COLOR_INFO = QColor("#fff9c4")
_COLOR_SKIP = QColor("#eeeeee")


class DiagnoseWorker(QThread):
    step_ready = pyqtSignal(dict)
    finished_all = pyqtSignal(list)

    def __init__(self, target: str, credential=None):
        super().__init__()
        self._target = target
        self._credential = credential

    def run(self):
        steps = []
        try:
            steps = diagnose.diagnose(self._target, self._credential, on_step=self.step_ready.emit)
        except Exception as exc:  # diagnose() reports its own failures; this is the last resort
            failed = diagnose._step("Diagnosis", False, None, f"{type(exc).__name__}: {exc}")
            self.step_ready.emit(failed)
            steps = [failed]
        finally:
            # Always emitted, or the Run button would stay disabled forever.
            self.finished_all.emit(steps)


class DiagnoseDialog(QDialog):
    def __init__(self, target: str = "", credential=None, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Diagnose a computer")
        self.resize(980, 600)
        self._credential = credential
        self._steps: list[dict] = []
        self._ran_target = ""
        self._worker = None

        layout = QVBoxLayout(self)

        row = QHBoxLayout()
        row.addWidget(QLabel("Computer name or IP:"))
        self.target_edit = QLineEdit(target)
        self.target_edit.setPlaceholderText("e.g. A-C14-PROV  or  10.20.30.5")
        self.target_edit.setToolTip(
            "If the name does not resolve, try its IP address instead — the scan "
            "may have found the machine by address."
        )
        row.addWidget(self.target_edit, 1)
        self.run_btn = QPushButton("Run")
        self.run_btn.setDefault(True)
        row.addWidget(self.run_btn)
        layout.addLayout(row)

        self.status_label = QLabel("Runs each check on its own so the failing layer is visible.")
        layout.addWidget(self.status_label)

        self.table = QTableWidget(0, len(HEADERS))
        self.table.setHorizontalHeaderLabels(HEADERS)
        header = self.table.horizontalHeader()
        header.setSectionResizeMode(QHeaderView.Interactive)
        header.setStretchLastSection(True)
        for col, width in enumerate([310, 70, 80]):
            self.table.setColumnWidth(col, width)
        self.table.setEditTriggers(QTableWidget.NoEditTriggers)
        layout.addWidget(self.table, 3)

        self.advice_label = QLabel("")
        self.advice_label.setWordWrap(True)
        layout.addWidget(self.advice_label)

        buttons = QHBoxLayout()
        self.copy_btn = QPushButton("Copy report")
        self.copy_btn.setToolTip("Copy a plain-text report to paste into a message. It never contains the password.")
        self.copy_btn.setEnabled(False)
        buttons.addWidget(self.copy_btn)
        buttons.addStretch(1)
        self.close_btn = QPushButton("Close")
        buttons.addWidget(self.close_btn)
        layout.addLayout(buttons)

        self.run_btn.clicked.connect(self.start)
        self.target_edit.returnPressed.connect(self.start)
        self.copy_btn.clicked.connect(self.copy_report)
        self.close_btn.clicked.connect(self.close)

    # ----- running -----

    def start(self):
        target = self.target_edit.text().strip()
        if not target:
            self.status_label.setText("Enter a computer name or IP address first.")
            return
        if self.is_running():
            return
        self._steps = []
        self._ran_target = target
        self.table.setRowCount(0)
        self.advice_label.setText("")
        self.run_btn.setEnabled(False)
        self.copy_btn.setEnabled(False)
        self.status_label.setText(f"Checking {target}… the Windows checks can take up to a minute on an "
                                  "unresponsive machine.")
        self._worker = DiagnoseWorker(target, self._credential)
        self._worker.step_ready.connect(self.on_step)
        self._worker.finished_all.connect(self.on_finished)
        self._worker.start()

    def is_running(self) -> bool:
        return self._worker is not None and self._worker.isRunning()

    def on_step(self, step: dict):
        self._steps.append(step)
        if step["ok"] is True:
            text, color = "OK", _COLOR_OK
        elif step["ok"] is None:
            text, color = "Skipped", _COLOR_SKIP
        elif step["optional"]:
            text, color = "Info", _COLOR_INFO
        else:
            text, color = "FAIL", _COLOR_FAIL
        timing = f"{step['ms']} ms" if step["ms"] is not None else ""
        row = self.table.rowCount()
        self.table.insertRow(row)
        for col, value in enumerate([step["name"], text, timing, step["detail"]]):
            item = QTableWidgetItem(value)
            item.setBackground(color)
            tip = step.get("error") or step["hint"]
            if tip:
                item.setToolTip(tip)
            self.table.setItem(row, col, item)

    def on_finished(self, steps: list):
        counts = diagnose.summarise(steps)
        self.status_label.setText(
            f"{counts['passed']} passed, {counts['failed']} failed, {counts['skipped']} skipped, "
            f"{counts['info']} informational."
        )
        hints = []
        for step in steps:
            if step["ok"] is False and not step["optional"] and step["hint"] and step["hint"] not in hints:
                hints.append(step["hint"])
        self.advice_label.setText("What to try:\n• " + "\n• ".join(hints) if hints else "")
        self.run_btn.setEnabled(True)
        self.copy_btn.setEnabled(bool(steps))

    # ----- report -----

    def report(self) -> str:
        return diagnose.format_report(self._ran_target or self.target_edit.text().strip(),
                                      self._steps, self._credential)

    def copy_report(self):
        QApplication.clipboard().setText(self.report())
        self.status_label.setText(self.status_label.text() + "  Report copied.")

    def closeEvent(self, event):
        # A PowerShell child can't be interrupted mid-call; let it finish on
        # its own and ignore the result.
        event.accept()
