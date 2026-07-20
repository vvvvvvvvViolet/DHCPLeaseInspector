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
        try:
            for row, computer in enumerate(self._computers):
                if self._stop_requested:
                    break
                try:
                    result = checks.check_computer(computer)
                except Exception as exc:
                    result = {"computer_name": computer, "ping": False, "error": str(exc)}
                self.row_ready.emit(row, result)
        finally:
            # Always emitted, even if a check blows up — otherwise the GUI
            # buttons stay disabled forever.
            self.finished_all.emit()
