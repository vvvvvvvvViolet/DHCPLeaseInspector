"""Software inventory: background worker plus the window that shows it."""
from concurrent.futures import ThreadPoolExecutor, as_completed

from PyQt5.QtCore import QThread, Qt, pyqtSignal
from PyQt5.QtGui import QColor
from PyQt5.QtWidgets import (
    QDialog,
    QFileDialog,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QMessageBox,
    QProgressBar,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
)

from . import config, export_excel, software

HEADERS = ["Computer", "Software", "Version", "Publisher", "Install Date", "Scope"]
_COLUMN_WIDTHS = [150, 300, 110, 200, 95, 120]
_COLOR_FAILED = QColor("#ffcdd2")
_COLOR_PARTIAL = QColor("#fff9c4")


class SoftwareWorker(QThread):
    result_ready = pyqtSignal(dict)
    progress = pyqtSignal(int, int)  # done, total
    finished_all = pyqtSignal()

    def __init__(self, targets: list[str], credential: tuple[str, str] | None = None):
        super().__init__()
        self._targets = targets
        self._credential = credential
        self._stop_requested = False

    def stop(self):
        self._stop_requested = True

    def _one(self, computer: str):
        # Queued machines bail out here once Cancel is pressed; the few
        # already running finish on their own (a PowerShell child can't be
        # interrupted mid-call) and their results are dropped.
        if self._stop_requested:
            return None
        try:
            return software.list_software(computer, credential=self._credential)
        except Exception as exc:
            return {"computer": computer, "ok": False, "partial": False, "apps": [], "error": str(exc)}

    def run(self):
        done = 0
        try:
            with ThreadPoolExecutor(max_workers=config.get_settings().max_parallel_wmi) as pool:
                futures = [pool.submit(self._one, target) for target in self._targets]
                for future in as_completed(futures):
                    result = future.result()
                    done += 1
                    if result is not None and not self._stop_requested:
                        self.result_ready.emit(result)
                    self.progress.emit(done, len(self._targets))
        finally:
            self.finished_all.emit()


class SoftwareWindow(QDialog):
    """Modeless window: the main table stays usable while this runs."""

    def __init__(self, targets: list[str], credential=None, parent=None):
        super().__init__(parent)
        self.setWindowTitle(f"Software Inventory — {len(targets)} computer(s)")
        self.resize(1120, 640)
        self._targets = targets
        self._credential = credential
        self._results: list[dict] = []
        self._worker = None

        layout = QVBoxLayout(self)

        self.summary_label = QLabel("")
        layout.addWidget(self.summary_label)

        progress_row = QHBoxLayout()
        self.progress = QProgressBar()
        self.progress.setFormat("%v / %m computers")
        self.progress.setMaximum(max(len(targets), 1))
        self.progress.setValue(0)  # an unset bar renders blank, not "0 / N"
        progress_row.addWidget(self.progress, 1)
        self.cancel_btn = QPushButton("Cancel")
        progress_row.addWidget(self.cancel_btn)
        layout.addLayout(progress_row)

        filter_row = QHBoxLayout()
        filter_row.addWidget(QLabel("Filter:"))
        self.filter_edit = QLineEdit()
        self.filter_edit.setPlaceholderText("software, publisher, version or computer — e.g. Chrome, Adobe, 7-Zip")
        filter_row.addWidget(self.filter_edit, 1)
        self.export_btn = QPushButton("Export Excel")
        self.export_btn.setEnabled(False)
        filter_row.addWidget(self.export_btn)
        layout.addLayout(filter_row)

        self.table = QTableWidget(0, len(HEADERS))
        self.table.setHorizontalHeaderLabels(HEADERS)
        header = self.table.horizontalHeader()
        header.setSectionResizeMode(QHeaderView.Interactive)
        header.setStretchLastSection(True)
        for col, width in enumerate(_COLUMN_WIDTHS):
            self.table.setColumnWidth(col, width)
        self.table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.table.setSelectionBehavior(QTableWidget.SelectRows)
        # Explicit A->Z: once sorting is switched on Qt applies the current
        # indicator, and its implicit default is column 0 *descending*.
        header.setSortIndicator(0, Qt.AscendingOrder)
        layout.addWidget(self.table)

        self.cancel_btn.clicked.connect(self.on_cancel)
        self.export_btn.clicked.connect(self.on_export)
        self.filter_edit.textChanged.connect(self.apply_filter)
        self._update_summary()

    # ----- scanning -----

    def start(self):
        # Rows are appended as results land; sorting stays off until the end
        # because a live sort reorders rows between cell writes.
        self.table.setSortingEnabled(False)
        self._worker = SoftwareWorker(self._targets, self._credential)
        self._worker.result_ready.connect(self.on_result)
        self._worker.progress.connect(self.on_progress)
        self._worker.finished_all.connect(self.on_finished)
        self._worker.start()

    def is_running(self) -> bool:
        return self._worker is not None and self._worker.isRunning()

    def on_cancel(self):
        if self.is_running():
            self._worker.stop()
            self.cancel_btn.setEnabled(False)
            self.cancel_btn.setText("Cancelling…")

    def on_progress(self, done: int, total: int):
        self.progress.setMaximum(max(total, 1))
        self.progress.setValue(done)
        self._update_summary()

    def _add_row(self, values, color=None, tooltip=None):
        row = self.table.rowCount()
        self.table.insertRow(row)
        for col, value in enumerate(values):
            item = QTableWidgetItem(value)
            if color is not None:
                item.setBackground(color)
            if tooltip:
                item.setToolTip(tooltip)
            self.table.setItem(row, col, item)
        return row

    def on_result(self, result: dict):
        self._results.append(result)
        was_sorting = self.table.isSortingEnabled()
        self.table.setSortingEnabled(False)
        computer = result["computer"]
        if not result["ok"]:
            error = result.get("error") or "Unknown error"
            # A failed machine stays visible as a red row rather than simply
            # being absent, which would read as "has no software".
            self._add_row([computer, "(scan failed)", "", error.splitlines()[0], "", ""],
                          _COLOR_FAILED, error)
        else:
            for app in result["apps"]:
                self._add_row([computer, app["name"], app["version"], app["publisher"],
                               app["install_date"], app["scope"]])
            if result.get("partial"):
                self._add_row([computer, "(list incomplete — connection dropped mid-read)",
                               "", result.get("error") or "", "", ""],
                              _COLOR_PARTIAL, result.get("error"))
        self.table.setSortingEnabled(was_sorting)
        self.export_btn.setEnabled(True)
        self.apply_filter(self.filter_edit.text())
        self._update_summary()

    def on_finished(self):
        self.cancel_btn.setEnabled(False)
        self.cancel_btn.setText("Done")
        self.table.setSortingEnabled(True)
        self._update_summary()

    # ----- presentation -----

    def _update_summary(self):
        ok = sum(1 for r in self._results if r["ok"])
        failed = sum(1 for r in self._results if not r["ok"])
        partial = sum(1 for r in self._results if r["ok"] and r.get("partial"))
        entries = sum(len(r["apps"]) for r in self._results)
        titles = len({a["name"].casefold() for r in self._results for a in r["apps"]})
        parts = [f"Computers {len(self._results)}/{len(self._targets)}", f"OK {ok}", f"Failed {failed}"]
        if partial:
            parts.append(f"Partial {partial}")
        parts += [f"Entries {entries}", f"Distinct titles {titles}"]
        self.summary_label.setText("  |  ".join(parts))

    def apply_filter(self, text: str):
        needle = text.strip().casefold()
        for row in range(self.table.rowCount()):
            if not needle:
                self.table.setRowHidden(row, False)
                continue
            haystack = " ".join(
                self.table.item(row, col).text() for col in range(self.table.columnCount())
                if self.table.item(row, col) is not None
            ).casefold()
            self.table.setRowHidden(row, needle not in haystack)

    # ----- export -----

    def on_export(self):
        if not self._results:
            return
        path, _ = QFileDialog.getSaveFileName(
            self, "Export Software Inventory", "software_inventory.xlsx", "Excel Files (*.xlsx)"
        )
        if not path:
            return
        try:
            self.export_to(path)
        except Exception as exc:
            QMessageBox.critical(self, "Export failed", str(exc))
            return
        QMessageBox.information(self, "Export complete", f"Saved to {path}")

    def export_to(self, path: str):
        # The whole inventory, not just the filtered view: the workbook has
        # its own filters, and a silently partial audit file is worse.
        export_excel.export_software(path, self._results)

    def closeEvent(self, event):
        if self.is_running():
            self._worker.stop()
        event.accept()
