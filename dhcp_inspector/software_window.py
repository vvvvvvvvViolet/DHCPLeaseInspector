"""Software inventory: background worker plus the window that shows it."""
from concurrent.futures import ThreadPoolExecutor, as_completed

from PyQt5.QtCore import QThread, Qt, pyqtSignal
from PyQt5.QtGui import QColor
from PyQt5.QtWidgets import (
    QDialog,
    QDialogButtonBox,
    QFileDialog,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPlainTextEdit,
    QProgressBar,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
)

from . import config, export_excel, policy as software_policy, software

HEADERS = ["Computer", "Software", "Version", "Publisher", "Install Date", "Scope", "Policy"]
_COLUMN_WIDTHS = [150, 290, 110, 190, 95, 110, 170]
_POLICY_COL = 6
_COLOR_FAILED = QColor("#ffcdd2")
_COLOR_PARTIAL = QColor("#fff9c4")
_COLOR_FORBIDDEN = QColor("#ffccbc")   # a forbidden title is installed
_COLOR_MISSING = QColor("#ffe0b2")     # a required title is absent


class PolicyDialog(QDialog):
    """Edit the forbidden / required software lists."""

    def __init__(self, policy: software_policy.Policy, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Software Policy")
        self.resize(560, 460)
        layout = QVBoxLayout(self)

        intro = QLabel(
            "One entry per line. Matching ignores case and finds the text anywhere in the "
            "software name, so  teamviewer  matches \"TeamViewer 15 Host\". Use * for any "
            "characters, e.g.  anydesk*  or  microsoft * 2019. Lines starting with # are ignored."
        )
        intro.setWordWrap(True)
        layout.addWidget(intro)

        layout.addWidget(QLabel("Forbidden — flagged on any computer that has it installed:"))
        self.forbidden_edit = QPlainTextEdit("\n".join(policy.forbidden))
        self.forbidden_edit.setPlaceholderText("AnyDesk\nTeamViewer\nuTorrent")
        layout.addWidget(self.forbidden_edit)

        layout.addWidget(QLabel("Required — flagged on any computer that is missing it:"))
        self.required_edit = QPlainTextEdit("\n".join(policy.required))
        self.required_edit.setPlaceholderText("Sophos\nMicrosoft Defender")
        layout.addWidget(self.required_edit)

        note = QLabel(
            "Computers that could not be scanned, or returned an incomplete list, are shown as "
            "Unknown — a missing title is only reported when the whole list was read."
        )
        note.setWordWrap(True)
        note.setStyleSheet("color: gray;")
        layout.addWidget(note)

        buttons = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)

    def policy(self) -> software_policy.Policy:
        return software_policy.Policy(
            forbidden=software_policy.parse_rules(self.forbidden_edit.toPlainText()),
            required=software_policy.parse_rules(self.required_edit.toPlainText()),
        )


def edit_policy(parent=None) -> software_policy.Policy | None:
    """Show the editor, save on OK. Returns the new policy, or None if cancelled."""
    dialog = PolicyDialog(software_policy.load_policy(), parent)
    if dialog.exec_() != QDialog.Accepted:
        return None
    new_policy = dialog.policy()
    try:
        software_policy.save_policy(new_policy)
    except OSError as exc:
        QMessageBox.critical(parent, "Software Policy", f"Could not save the policy: {exc}")
        return None
    return new_policy


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
        self._policy = software_policy.load_policy()

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
        self.policy_btn = QPushButton("Policy…")
        self.policy_btn.setToolTip("Edit the lists of forbidden and required software")
        filter_row.addWidget(self.policy_btn)
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
        self.policy_btn.clicked.connect(self.on_edit_policy)
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

    def _rows_for(self, result: dict):
        """The table rows for one computer: (values, colour, tooltip) each."""
        computer = result["computer"]
        use_policy = not self._policy.empty
        verdict = software_policy.evaluate(result, self._policy) if use_policy else None
        rows = []

        if not result["ok"]:
            error = result.get("error") or "Unknown error"
            # A failed machine stays visible as a red row rather than simply
            # being absent, which would read as "has no software".
            rows.append(([computer, "(scan failed)", "", error.splitlines()[0], "", "",
                          software_policy.UNKNOWN if use_policy else ""], _COLOR_FAILED, error))
            return rows

        flagged = {}
        if verdict:
            for rule, app in verdict["forbidden"]:
                flagged.setdefault(id(app), []).append(rule)
        for app in result["apps"]:
            rules = flagged.get(id(app))
            policy_text = "Forbidden: " + ", ".join(rules) if rules else ""
            rows.append(([computer, app["name"], app["version"], app["publisher"],
                          app["install_date"], app["scope"], policy_text],
                         _COLOR_FORBIDDEN if rules else None, None))

        if result.get("partial"):
            rows.append(([computer, "(list incomplete — connection dropped mid-read)", "",
                          result.get("error") or "", "", "",
                          software_policy.UNKNOWN if use_policy else ""],
                         _COLOR_PARTIAL, result.get("error")))
        if verdict:
            for rule in verdict["missing"]:
                rows.append(([computer, f"(missing required: {rule})", "", "", "", "",
                              "Missing required"], _COLOR_MISSING, None))
        return rows

    def on_result(self, result: dict):
        self._results.append(result)
        was_sorting = self.table.isSortingEnabled()
        self.table.setSortingEnabled(False)
        for values, color, tooltip in self._rows_for(result):
            self._add_row(values, color, tooltip)
        self.table.setSortingEnabled(was_sorting)
        self.export_btn.setEnabled(True)
        self.apply_filter(self.filter_edit.text())
        self._update_summary()

    def rebuild(self):
        """Redraw every result, e.g. after the policy changed."""
        was_sorting = self.table.isSortingEnabled()
        self.table.setSortingEnabled(False)
        self.table.setRowCount(0)
        for result in self._results:
            for values, color, tooltip in self._rows_for(result):
                self._add_row(values, color, tooltip)
        self.table.setSortingEnabled(was_sorting)
        self.apply_filter(self.filter_edit.text())
        self._update_summary()

    def on_edit_policy(self):
        new_policy = edit_policy(self)
        if new_policy is None:
            return
        self._policy = new_policy
        self.rebuild()

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
        if not self._policy.empty:
            verdicts = [software_policy.evaluate(r, self._policy)["status"] for r in self._results]
            parts += [f"Violations {verdicts.count(software_policy.VIOLATION)}",
                      f"Compliant {verdicts.count(software_policy.COMPLIANT)}",
                      f"Unknown {verdicts.count(software_policy.UNKNOWN)}"]
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
        export_excel.export_software(path, self._results, self._policy)

    def closeEvent(self, event):
        if self.is_running():
            self._worker.stop()
        event.accept()
