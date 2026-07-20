"""Single-page PyQt5 GUI: Load AD / Check Status / Export Excel."""
import sys

from PyQt5.QtWidgets import (
    QApplication,
    QFileDialog,
    QHeaderView,
    QMainWindow,
    QMessageBox,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from . import ad_utils, export_excel, scoring
from .worker import ScanWorker

HEADERS = ["Computer", "Ping", "Domain", "DHCP Server", "WSUS", "OS Version", "Uptime", "Score", "Status"]


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("DHCP Lease Inspector")
        self.resize(950, 520)

        self._worker = None

        central = QWidget()
        layout = QVBoxLayout(central)

        self.load_ad_btn = QPushButton("Load AD")
        self.check_status_btn = QPushButton("Check Status")
        self.export_btn = QPushButton("Export Excel")

        self.load_ad_btn.clicked.connect(self.on_load_ad)
        self.check_status_btn.clicked.connect(self.on_check_status)
        self.export_btn.clicked.connect(self.on_export_excel)

        layout.addWidget(self.load_ad_btn)
        layout.addWidget(self.check_status_btn)
        layout.addWidget(self.export_btn)

        self.table = QTableWidget(0, len(HEADERS))
        self.table.setHorizontalHeaderLabels(HEADERS)
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.table.setEditTriggers(QTableWidget.NoEditTriggers)
        layout.addWidget(self.table)

        self.setCentralWidget(central)

    def on_load_ad(self):
        self.load_ad_btn.setEnabled(False)
        try:
            computers = ad_utils.load_ad_computers()
        except Exception as exc:
            QMessageBox.critical(self, "Load AD failed", str(exc))
            return
        finally:
            self.load_ad_btn.setEnabled(True)

        self.table.setRowCount(0)
        for name in computers:
            row = self.table.rowCount()
            self.table.insertRow(row)
            self.table.setItem(row, 0, QTableWidgetItem(name))
            for col in range(1, len(HEADERS)):
                self.table.setItem(row, col, QTableWidgetItem("-"))

    def on_check_status(self):
        if self.table.rowCount() == 0:
            QMessageBox.information(self, "No computers", "Load AD first to populate the computer list.")
            return
        if self._worker is not None and self._worker.isRunning():
            return

        computers = [self.table.item(row, 0).text() for row in range(self.table.rowCount())]

        self.check_status_btn.setEnabled(False)
        self.load_ad_btn.setEnabled(False)

        self._worker = ScanWorker(computers)
        self._worker.row_ready.connect(self.on_row_ready)
        self._worker.finished_all.connect(self.on_scan_finished)
        self._worker.start()

    def on_row_ready(self, row: int, result: dict):
        score, status = scoring.compute_score(result)
        uptime = scoring.compute_uptime_str(result.get("last_boot"))

        domain_cell = "-"
        if result.get("part_of_domain") is True:
            domain_cell = result.get("domain") or "-"
        elif result.get("part_of_domain") is False:
            domain_cell = "Not Joined"

        values = [
            result["computer_name"],
            "OK" if result["ping"] else "Fail",
            domain_cell,
            result.get("dhcp_server") or "-",
            result.get("wsus") or "Not Configured",
            result.get("os_version") or "-",
            uptime,
            str(score),
            status,
        ]
        for col, value in enumerate(values):
            self.table.setItem(row, col, QTableWidgetItem(value))

    def on_scan_finished(self):
        self.check_status_btn.setEnabled(True)
        self.load_ad_btn.setEnabled(True)

    def on_export_excel(self):
        if self.table.rowCount() == 0:
            QMessageBox.information(self, "Nothing to export", "Load AD and run Check Status first.")
            return

        path, _ = QFileDialog.getSaveFileName(
            self, "Export Excel", "dhcp_lease_inspector_report.xlsx", "Excel Files (*.xlsx)"
        )
        if not path:
            return

        rows = [
            [self.table.item(row, col).text() if self.table.item(row, col) else "" for col in range(len(HEADERS))]
            for row in range(self.table.rowCount())
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
            self._worker.wait(2000)
        event.accept()


def main():
    app = QApplication(sys.argv)
    window = MainWindow()
    window.show()
    sys.exit(app.exec_())


if __name__ == "__main__":
    main()
