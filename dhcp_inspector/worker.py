"""QThread worker that scans computers in parallel off the GUI thread."""
from concurrent.futures import ThreadPoolExecutor, as_completed

from PyQt5.QtCore import QThread, pyqtSignal

from . import checks

_MAX_PARALLEL = 15


class ScanWorker(QThread):
    row_ready = pyqtSignal(int, dict)
    progress = pyqtSignal(int, int)  # done, total
    finished_all = pyqtSignal()

    def __init__(self, computers: list[str]):
        super().__init__()
        self._computers = computers
        self._stop_requested = False

    def stop(self):
        self._stop_requested = True

    def _check_one(self, computer: str) -> dict:
        try:
            return checks.check_computer(computer)
        except Exception as exc:
            return {"computer_name": computer, "ping": False, "error": str(exc)}

    def run(self):
        total = len(self._computers)
        done = 0
        try:
            with ThreadPoolExecutor(max_workers=_MAX_PARALLEL) as pool:
                futures = {
                    pool.submit(self._check_one, computer): row
                    for row, computer in enumerate(self._computers)
                }
                for future in as_completed(futures):
                    if self._stop_requested:
                        for pending in futures:
                            pending.cancel()
                        break
                    self.row_ready.emit(futures[future], future.result())
                    done += 1
                    self.progress.emit(done, total)
        finally:
            # Always emitted, even if a check blows up — otherwise the GUI
            # buttons stay disabled forever.
            self.finished_all.emit()
