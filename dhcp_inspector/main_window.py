"""Single-page PyQt5 GUI: Load AD / Check Status / Export Excel."""
import sys

from PyQt5.QtGui import QColor
from PyQt5.QtWidgets import (
    QApplication,
    QComboBox,
    QFileDialog,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QMainWindow,
    QMessageBox,
    QProgressBar,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from . import ad_utils, export_excel, scoring
from .worker import ScanWorker

HEADERS = ["Computer", "Ping", "Domain", "DHCP Server", "WSUS", "OS Version", "Uptime", "Score", "Status"]
_SCORE_COL = 7
_STATUS_COL = 8

_COLOR_GOOD = QColor("#c8e6c9")   # green  — Ready
_COLOR_WARN = QColor("#fff9c4")   # yellow — Needs Attention
_COLOR_BAD = QColor("#ffcdd2")    # red    — Offline / Error

_STATUS_FILTERS = ["All", "Ready", "Needs Attention", "Offline", "Error"]


class _NumericItem(QTableWidgetItem):
    """Table item that sorts by numeric value instead of as text."""

    def __lt__(self, other):
        try:
            return float(self.text()) < float(other.text())
        except ValueError:
            return super().__lt__(other)


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("DHCP Lease Inspector")
        self.resize(980, 560)

        self._worker = None

        central = QWidget()
        layout = QVBoxLayout(central)

        # Row 1: AD name filter + Load AD
        ad_row = QHBoxLayout()
        ad_row.addWidget(QLabel("Name filter:"))
        self.ad_filter_edit = QLineEdit()
        self.ad_filter_edit.setPlaceholderText("Optional: substring of computer name, e.g. PC- or LAB")
        ad_row.addWidget(self.ad_filter_edit, 1)
        self.load_ad_btn = QPushButton("Load AD")
        ad_row.addWidget(self.load_ad_btn)
        layout.addLayout(ad_row)

        # Row 2: scan controls + status filter + export
        scan_row = QHBoxLayout()
        self.check_status_btn = QPushButton("Check Status")
        self.cancel_btn = QPushButton("Cancel")
        self.cancel_btn.setEnabled(False)
        self.export_btn = QPushButton("Export Excel")
        scan_row.addWidget(self.check_status_btn)
        scan_row.addWidget(self.cancel_btn)
        scan_row.addStretch(1)
        scan_row.addWidget(QLabel("Show:"))
        self.status_filter = QComboBox()
        self.status_filter.addItems(_STATUS_FILTERS)
        scan_row.addWidget(self.status_filter)
        scan_row.addWidget(self.export_btn)
        layout.addLayout(scan_row)

        self.progress = QProgressBar()
        self.progress.setFormat("%v / %m")
        self.progress.setValue(0)
        self.progress.setMaximum(1)
        layout.addWidget(self.progress)

        self.table = QTableWidget(0, len(HEADERS))
        self.table.setHorizontalHeaderLabels(HEADERS)
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.table.setSortingEnabled(True)
        layout.addWidget(self.table)

        self.setCentralWidget(central)

        self.load_ad_btn.clicked.connect(self.on_load_ad)
        self.check_status_btn.clicked.connect(self.on_check_status)
        self.cancel_btn.clicked.connect(self.on_cancel)
        self.export_btn.clicked.connect(self.on_export_excel)
        self.status_filter.currentTextChanged.connect(self.apply_status_filter)

    def on_load_ad(self):
        self.load_ad_btn.setEnabled(False)
        try:
            computers = ad_utils.load_ad_computers(self.ad_filter_edit.text())
        except Exception as exc:
            QMessageBox.critical(self, "Load AD failed", str(exc))
            return
        finally:
            self.load_ad_btn.setEnabled(True)

        self.table.setSortingEnabled(False)
        self.table.setRowCount(0)
        for name in computers:
            row = self.table.rowCount()
            self.table.insertRow(row)
            self.table.setItem(row, 0, QTableWidgetItem(name))
            for col in range(1, len(HEADERS)):
                self.table.setItem(row, col, QTableWidgetItem("-"))
        self.table.setSortingEnabled(True)
        self.progress.setValue(0)
        self.progress.setMaximum(max(len(computers), 1))
        if not computers:
            QMessageBox.information(self, "Load AD", "No computers matched.")

    def on_check_status(self):
        if self.table.rowCount() == 0:
            QMessageBox.information(self, "No computers", "Load AD first to populate the computer list.")
            return
        if self._worker is not None and self._worker.isRunning():
            return

        # Row indexes coming back from the worker map to table rows, so the
        # order must not shift mid-scan.
        self.table.setSortingEnabled(False)
        self.status_filter.setCurrentIndex(0)

        computers = [self.table.item(row, 0).text() for row in range(self.table.rowCount())]

        self.check_status_btn.setEnabled(False)
        self.load_ad_btn.setEnabled(False)
        self.cancel_btn.setEnabled(True)
        self.progress.setValue(0)
        self.progress.setMaximum(len(computers))

        self._worker = ScanWorker(computers)
        self._worker.row_ready.connect(self.on_row_ready)
        self._worker.progress.connect(self.on_progress)
        self._worker.finished_all.connect(self.on_scan_finished)
        self._worker.start()

    def on_cancel(self):
        if self._worker is not None and self._worker.isRunning():
            self._worker.stop()
            self.cancel_btn.setEnabled(False)

    def on_progress(self, done: int, total: int):
        self.progress.setMaximum(total)
        self.progress.setValue(done)

    @staticmethod
    def _row_color(score: int, status: str) -> QColor:
        if status in ("Offline", "Error"):
            return _COLOR_BAD
        if score >= 75:
            return _COLOR_GOOD
        return _COLOR_WARN

    def on_row_ready(self, row: int, result: dict):
        score, status = scoring.compute_score(result)
        uptime = scoring.compute_uptime_str(result.get("last_boot"))
        error = result.get("error")
        color = self._row_color(score, status)

        domain_cell = "-"
        if result.get("part_of_domain") is True:
            domain_cell = result.get("domain") or "-"
        elif result.get("part_of_domain") is False:
            domain_cell = "Not Joined"

        values = [
            result["computer_name"],
            "OK" if result.get("ping") else "Fail",
            domain_cell,
            result.get("dhcp_server") or "-",
            result.get("wsus") or "Not Configured",
            result.get("os_version") or "-",
            uptime,
            str(score),
            status,
        ]
        for col, value in enumerate(values):
            item = _NumericItem(value) if col == _SCORE_COL else QTableWidgetItem(value)
            item.setBackground(color)
            # Full failure reason (e.g. Access Denied vs timeout) lives in the
            # tooltip so it isn't lost behind a bare "-" or "Offline".
            if error:
                item.setToolTip(error)
            self.table.setItem(row, col, item)

    def on_scan_finished(self):
        self.check_status_btn.setEnabled(True)
        self.load_ad_btn.setEnabled(True)
        self.cancel_btn.setEnabled(False)
        self.table.setSortingEnabled(True)
        self.apply_status_filter(self.status_filter.currentText())

    def apply_status_filter(self, wanted: str):
        for row in range(self.table.rowCount()):
            item = self.table.item(row, _STATUS_COL)
            status = item.text() if item else ""
            self.table.setRowHidden(row, wanted != "All" and status != wanted)

    def on_export_excel(self):
        if self.table.rowCount() == 0:
            QMessageBox.information(self, "Nothing to export", "Load AD and run Check Status first.")
            return

        path, _ = QFileDialog.getSaveFileName(
            self, "Export Excel", "dhcp_lease_inspector_report.xlsx", "Excel Files (*.xlsx)"
        )
        if not path:
            return

        # Export follows what's on screen: current sort order, hidden rows
        # (filtered out) excluded.
        rows = [
            [self.table.item(row, col).text() if self.table.item(row, col) else "" for col in range(len(HEADERS))]
            for row in range(self.table.rowCount())
            if not self.table.isRowHidden(row)
        ]

        try:
            export_excel.export_to_excel(path, rows, HEADERS)
        except Exception as exc:
            QMessageBox.critical(self, "Export failed", str(exc))
            return

        QMessageBox.information(self, "Export complete", f"Saved to {path}")

    def closeEvent(self, event):
        if self._worker is not None and self._worker.isRunning():
            self._worker.stop()
            self._worker.wait(5000)
        event.accept()


def main():
    app = QApplication(sys.argv)
    window = MainWindow()
    window.show()
    sys.exit(app.exec_())


if __name__ == "__main__":
    main()
