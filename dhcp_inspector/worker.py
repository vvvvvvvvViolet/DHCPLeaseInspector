"""QThread worker that runs the per-computer scan off the GUI thread."""
from PyQt5.QtCore import QThread, pyqtSignal

from . import checks


class ScanWorker(QThread):
    row_ready = pyqtSignal(int, dict)
    finished_all = pyqtSignal()

    def __init__(self, computers: list[str]):
        super().__init__()
        self._computers = computers
        self._stop_requested = False

    def stop(self):
        self._stop_requested = True

    def run(self):
        for row, computer in enumerate(self._computers):
            if self._stop_requested:
                break
            result = checks.check_computer(computer)
            self.row_ready.emit(row, result)
        self.finished_all.emit()
