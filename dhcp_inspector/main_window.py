"""Single-page PyQt5 GUI: Load AD / Check Status / Export Excel."""
import sys
from collections import Counter

from PyQt5.QtCore import Qt
from PyQt5.QtGui import QColor
from PyQt5.QtWidgets import (
    QApplication,
    QCheckBox,
    QComboBox,
    QDialog,
    QDialogButtonBox,
    QFileDialog,
    QFormLayout,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QMainWindow,
    QMessageBox,
    QProgressBar,
    QPushButton,
    QSpinBox,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from . import ad_utils, config, export_excel, history, scoring
from .worker import ScanWorker

HEADERS = ["Computer", "IP", "Ping", "Domain", "DHCP Server", "OS Version",
           "Uptime", "Last Logon", "Last Patch", "Status", "Change"]
_LAST_LOGON_COL = 7
_LAST_PATCH_COL = 8
_STATUS_COL = 9
_CHANGE_COL = 10

_COLOR_GOOD = QColor("#c8e6c9")   # green  — Ready
_COLOR_WARN = QColor("#fff9c4")   # yellow — Domain Issue / Patch Overdue
_COLOR_BAD = QColor("#ffcdd2")    # red    — Offline / Error / No DNS

_STATUSES = ["Ready", "Domain Issue", "Patch Overdue", "Offline", "Error", "No DNS"]
_FAILED_STATUSES = ("Offline", "Error", "No DNS")


class SettingsDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Settings")
        settings = config.get_settings()

        form = QFormLayout(self)

        self.stale_days = QSpinBox()
        self.stale_days.setRange(1, 3650)
        self.stale_days.setValue(settings.stale_password_days)
        form.addRow("Stale password threshold (days):", self.stale_days)

        self.stale_patch_days = QSpinBox()
        self.stale_patch_days.setRange(1, 3650)
        self.stale_patch_days.setValue(settings.stale_patch_days)
        form.addRow("Patch overdue threshold (days):", self.stale_patch_days)

        self.parallel_ping = QSpinBox()
        self.parallel_ping.setRange(1, 256)
        self.parallel_ping.setValue(settings.max_parallel_ping)
        form.addRow("Parallel pings (phase 1):", self.parallel_ping)

        self.parallel_wmi = QSpinBox()
        self.parallel_wmi.setRange(1, 64)
        self.parallel_wmi.setValue(settings.max_parallel_wmi)
        form.addRow("Parallel WMI checks (phase 2):", self.parallel_wmi)

        self.ping_timeout = QSpinBox()
        self.ping_timeout.setRange(100, 30000)
        self.ping_timeout.setSingleStep(100)
        self.ping_timeout.setValue(settings.ping_timeout_ms)
        form.addRow("Ping timeout (ms):", self.ping_timeout)

        self.wmi_timeout = QSpinBox()
        self.wmi_timeout.setRange(5, 600)
        self.wmi_timeout.setValue(settings.wmi_timeout_s)
        form.addRow("WMI timeout per machine (s):", self.wmi_timeout)

        self.wmi_only_ping_ok = QCheckBox("Skip WMI for machines that failed ping")
        self.wmi_only_ping_ok.setChecked(settings.wmi_only_ping_ok)
        self.wmi_only_ping_ok.setToolTip(
            "Uncheck to also try WMI on ping-failed machines (finds hosts that "
            "block ICMP but allow WMI — much slower on large fleets)."
        )
        form.addRow(self.wmi_only_ping_ok)

        buttons = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        form.addRow(buttons)

    def save(self):
        config.save_settings(config.Settings(
            stale_password_days=self.stale_days.value(),
            stale_patch_days=self.stale_patch_days.value(),
            max_parallel_ping=self.parallel_ping.value(),
            max_parallel_wmi=self.parallel_wmi.value(),
            ping_timeout_ms=self.ping_timeout.value(),
            wmi_timeout_s=self.wmi_timeout.value(),
            wmi_only_ping_ok=self.wmi_only_ping_ok.isChecked(),
        ))


class CredentialsDialog(QDialog):
    """Collects an alternate account for the remote WMI connection.

    Credentials live only in memory for the session — they are never written
    to settings, history, or the command line.
    """

    def __init__(self, credential: tuple[str, str] | None = None, parent=None):
        super().__init__(parent)
        self.setWindowTitle("WMI Credentials")

        form = QFormLayout(self)

        self.enabled = QCheckBox("Use alternate credentials for WMI checks")
        self.enabled.setChecked(credential is not None)
        form.addRow(self.enabled)

        self.username = QLineEdit(credential[0] if credential else "")
        self.username.setPlaceholderText(r"DOMAIN\admin  or  admin@domain")
        form.addRow("Username:", self.username)

        self.password = QLineEdit(credential[1] if credential else "")
        self.password.setEchoMode(QLineEdit.Password)
        form.addRow("Password:", self.password)

        note = QLabel(
            "Held in memory for this session only — not saved to disk or the\n"
            "command line. Needs local-admin rights on the target machines."
        )
        note.setStyleSheet("color: gray;")
        form.addRow(note)

        self.enabled.toggled.connect(self._sync_enabled)
        self._sync_enabled(self.enabled.isChecked())

        buttons = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        form.addRow(buttons)

    def _sync_enabled(self, on: bool):
        self.username.setEnabled(on)
        self.password.setEnabled(on)

    def credential(self) -> tuple[str, str] | None:
        if not self.enabled.isChecked() or not self.username.text().strip():
            return None
        return (self.username.text().strip(), self.password.text())


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("DHCP Lease Inspector")
        self.resize(1180, 620)

        self._worker = None
        self._ad_info = {}            # computer name -> AD record
        self._status_counts = Counter()  # live counts for the summary line
        self._prev_run = None         # snapshot loaded when a scan starts
        self._credential = None       # (username, password) in memory only

        central = QWidget()
        layout = QVBoxLayout(central)

        # Row 1: AD name filter + Load AD + Settings
        ad_row = QHBoxLayout()
        ad_row.addWidget(QLabel("Name filter:"))
        self.ad_filter_edit = QLineEdit()
        self.ad_filter_edit.setPlaceholderText("Optional: substring of computer name, e.g. PC- or LAB")
        ad_row.addWidget(self.ad_filter_edit, 1)
        self.load_ad_btn = QPushButton("Load AD")
        ad_row.addWidget(self.load_ad_btn)
        self.credentials_btn = QPushButton("Credentials")
        ad_row.addWidget(self.credentials_btn)
        self.settings_btn = QPushButton("Settings")
        ad_row.addWidget(self.settings_btn)
        layout.addLayout(ad_row)

        # Row 2: scan controls + status filter + export
        scan_row = QHBoxLayout()
        self.check_status_btn = QPushButton("Check Status")
        self.recheck_btn = QPushButton("Re-check Failed")
        self.cancel_btn = QPushButton("Cancel")
        self.cancel_btn.setEnabled(False)
        self.export_btn = QPushButton("Export Excel")
        scan_row.addWidget(self.check_status_btn)
        scan_row.addWidget(self.recheck_btn)
        scan_row.addWidget(self.cancel_btn)
        scan_row.addStretch(1)
        scan_row.addWidget(QLabel("Show:"))
        self.status_filter = QComboBox()
        self.status_filter.addItems(["All"] + _STATUSES)
        scan_row.addWidget(self.status_filter)
        scan_row.addWidget(self.export_btn)
        layout.addLayout(scan_row)

        # Progress + phase + summary
        progress_row = QHBoxLayout()
        self.phase_label = QLabel("")
        progress_row.addWidget(self.phase_label)
        self.progress = QProgressBar()
        self.progress.setFormat("%v / %m")
        self.progress.setValue(0)
        self.progress.setMaximum(1)
        progress_row.addWidget(self.progress, 1)
        layout.addLayout(progress_row)

        self.summary_label = QLabel("No computers loaded.")
        layout.addWidget(self.summary_label)

        self.table = QTableWidget(0, len(HEADERS))
        self.table.setHorizontalHeaderLabels(HEADERS)
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.table.setEditTriggers(QTableWidget.NoEditTriggers)
        # Explicit A->Z default: re-enabling sorting re-applies the current
        # indicator, and Qt's implicit default is column 0 descending.
        self.table.horizontalHeader().setSortIndicator(0, Qt.AscendingOrder)
        self.table.setSortingEnabled(True)
        layout.addWidget(self.table)

        self.setCentralWidget(central)

        self.load_ad_btn.clicked.connect(self.on_load_ad)
        self.credentials_btn.clicked.connect(self.on_credentials)
        self.settings_btn.clicked.connect(self.on_settings)
        self.check_status_btn.clicked.connect(self.on_check_status)
        self.recheck_btn.clicked.connect(self.on_recheck_failed)
        self.cancel_btn.clicked.connect(self.on_cancel)
        self.export_btn.clicked.connect(self.on_export_excel)
        self.status_filter.currentTextChanged.connect(self.apply_status_filter)

    # ----- summary -----

    def _row_status_text(self, row: int) -> str:
        item = self.table.item(row, _STATUS_COL)
        return item.text() if item else "-"

    def _update_summary(self):
        total = self.table.rowCount()
        parts = [f"Total {total}"]
        parts += [f"{status} {self._status_counts.get(status, 0)}" for status in _STATUSES]
        unscanned = total - sum(self._status_counts.values())
        if unscanned:
            parts.append(f"Unscanned {unscanned}")
        self.summary_label.setText("  |  ".join(parts))

    # ----- actions -----

    def on_credentials(self):
        dialog = CredentialsDialog(self._credential, self)
        if dialog.exec_() == QDialog.Accepted:
            self._credential = dialog.credential()
            self._refresh_credentials_button()

    def _refresh_credentials_button(self):
        if self._credential:
            self.credentials_btn.setText("Credentials ✓")
            self.credentials_btn.setToolTip(f"WMI runs as {self._credential[0]}")
        else:
            self.credentials_btn.setText("Credentials")
            self.credentials_btn.setToolTip("WMI runs as the current user")

    def on_settings(self):
        dialog = SettingsDialog(self)
        if dialog.exec_() == QDialog.Accepted:
            dialog.save()

    def on_load_ad(self):
        self.load_ad_btn.setEnabled(False)
        try:
            records = ad_utils.load_ad_computers(self.ad_filter_edit.text())
        except Exception as exc:
            QMessageBox.critical(self, "Load AD failed", str(exc))
            return
        finally:
            self.load_ad_btn.setEnabled(True)

        self._ad_info = {r["name"]: r for r in records if r.get("name")}

        self.table.setSortingEnabled(False)
        self.table.setRowCount(0)
        self._status_counts = Counter()
        for record in records:
            name = record.get("name")
            if not name:
                continue
            row = self.table.rowCount()
            self.table.insertRow(row)
            self.table.setItem(row, 0, QTableWidgetItem(name))
            # Pre-fill everything AD already knows, so the list is useful
            # before (or without) a live scan.
            self.table.setItem(row, 3, QTableWidgetItem(record.get("domain") or "-"))
            self.table.setItem(row, 5, QTableWidgetItem(record.get("ad_os") or "-"))
            logon_text, logon_tip = scoring.format_last_logon(record.get("last_logon"))
            logon_item = QTableWidgetItem(logon_text)
            if logon_tip:
                logon_item.setToolTip(logon_tip)
            self.table.setItem(row, _LAST_LOGON_COL, logon_item)
            for col in (1, 2, 4, 6, _LAST_PATCH_COL, _STATUS_COL, _CHANGE_COL):
                self.table.setItem(row, col, QTableWidgetItem("-"))
        self.table.setSortingEnabled(True)
        self.progress.setValue(0)
        self.progress.setMaximum(max(self.table.rowCount(), 1))
        self.phase_label.setText("")
        self._update_summary()
        if self.table.rowCount() == 0:
            QMessageBox.information(self, "Load AD", "No computers matched.")

    def _start_scan(self, targets: list[tuple[int, str]]):
        # Row indexes coming back from the worker map to table rows, so the
        # order must not shift mid-scan.
        self.table.setSortingEnabled(False)
        self.status_filter.setCurrentIndex(0)
        self._prev_run = history.last_run()

        self.check_status_btn.setEnabled(False)
        self.recheck_btn.setEnabled(False)
        self.load_ad_btn.setEnabled(False)
        self.cancel_btn.setEnabled(True)
        self.progress.setValue(0)
        self.progress.setMaximum(len(targets))
        self.phase_label.setText("Ping sweep")

        self._worker = ScanWorker(targets, self._ad_info, self._credential)
        self._worker.row_ready.connect(self.on_row_ready)
        self._worker.progress.connect(self.on_progress)
        self._worker.finished_all.connect(self.on_scan_finished)
        self._worker.start()

    def on_check_status(self):
        if self.table.rowCount() == 0:
            QMessageBox.information(self, "No computers", "Load AD first to populate the computer list.")
            return
        if self._worker is not None and self._worker.isRunning():
            return
        targets = [(row, self.table.item(row, 0).text()) for row in range(self.table.rowCount())]
        self._start_scan(targets)

    def on_recheck_failed(self):
        if self._worker is not None and self._worker.isRunning():
            return
        targets = [
            (row, self.table.item(row, 0).text())
            for row in range(self.table.rowCount())
            if self._row_status_text(row) in _FAILED_STATUSES
        ]
        if not targets:
            QMessageBox.information(self, "Re-check Failed", "No failed rows to re-check.")
            return
        self._start_scan(targets)

    def on_cancel(self):
        if self._worker is not None and self._worker.isRunning():
            self._worker.stop()
            self.cancel_btn.setEnabled(False)

    def on_progress(self, done: int, total: int, phase: str):
        self.progress.setMaximum(max(total, 1))
        self.progress.setValue(done)
        self.phase_label.setText(phase)

    @staticmethod
    def _status_color(status: str) -> QColor:
        if status == "Ready":
            return _COLOR_GOOD
        if status in ("Domain Issue", "Patch Overdue"):
            return _COLOR_WARN
        return _COLOR_BAD  # Offline / Error / No DNS

    def on_row_ready(self, row: int, result: dict):
        status = scoring.compute_status(result)
        old_status = self._row_status_text(row)
        if old_status != "-":
            self._status_counts[old_status] -= 1
        self._status_counts[status] += 1
        uptime = scoring.compute_uptime_str(result.get("last_boot"))
        error = result.get("error")
        color = self._status_color(status)
        logon_text, logon_tip = scoring.format_last_logon(result.get("ad_last_logon"))
        patch_text, patch_tip = scoring.format_last_patch(
            result.get("last_patch"), result.get("recent_hotfixes")
        )

        ping_text = "OK" if result.get("ping") else "Fail"
        if result.get("dns_ok") is False:
            ping_text = "No DNS"

        change_item = self.table.item(row, _CHANGE_COL)
        values = [
            result["computer_name"],
            result.get("ip") or "-",
            ping_text,
            scoring.domain_label(result),
            result.get("dhcp_server") or "-",
            result.get("os_version") or result.get("ad_os") or "-",
            uptime,
            logon_text,
            patch_text,
            status,
            change_item.text() if change_item else "-",
        ]
        for col, value in enumerate(values):
            item = QTableWidgetItem(value)
            item.setBackground(color)
            # Full failure reason (e.g. Access Denied vs timeout) lives in the
            # tooltip so it isn't lost behind a bare "-" or "Offline".
            if error:
                item.setToolTip(error)
            if col == _LAST_LOGON_COL and logon_tip:
                item.setToolTip(logon_tip)
            if col == _LAST_PATCH_COL and patch_tip:
                item.setToolTip(patch_tip)
            self.table.setItem(row, col, item)

        self._update_summary()

    def _fill_change_column(self):
        prev_statuses = (self._prev_run or {}).get("statuses", {})
        for row in range(self.table.rowCount()):
            current = self._row_status_text(row)
            if current == "-":
                continue
            name = self.table.item(row, 0).text()
            prev = prev_statuses.get(name)
            if prev is None:
                text = "New" if prev_statuses else "-"
            elif prev == current:
                text = "-"
            else:
                text = f"{prev} → {current}"
            item = QTableWidgetItem(text)
            status_item = self.table.item(row, _STATUS_COL)
            if status_item is not None:
                item.setBackground(status_item.background())
            if prev is not None and prev != current:
                item.setToolTip(f"Previous run: {prev} ({(self._prev_run or {}).get('timestamp', '')})")
            self.table.setItem(row, _CHANGE_COL, item)

    def on_scan_finished(self):
        self._fill_change_column()
        # Persist the whole table's latest known statuses as this run.
        statuses = {
            self.table.item(row, 0).text(): self._row_status_text(row)
            for row in range(self.table.rowCount())
            if self._row_status_text(row) != "-"
        }
        if statuses:
            try:
                history.save_run(statuses)
            except OSError:
                pass  # history is best-effort; never block the UI on it

        self.check_status_btn.setEnabled(True)
        self.recheck_btn.setEnabled(True)
        self.load_ad_btn.setEnabled(True)
        self.cancel_btn.setEnabled(False)
        self.phase_label.setText("Done")
        self.table.setSortingEnabled(True)
        self.apply_status_filter(self.status_filter.currentText())
        self._update_summary()

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
