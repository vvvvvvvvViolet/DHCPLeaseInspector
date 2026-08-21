#!/usr/bin/env python3
"""REPL driver for DHCP Lease Inspector: stdin commands -> Qt actions.

The app is a PyQt5 desktop GUI written for Windows. A headless agent
can't see its window, so this exposes it as a line protocol: pipe
commands in (batch) or drive it from tmux (interactive). Every command
prints its result then `OK` or `ERR <message>`.

Run it under xvfb — see SKILL.md. Commands:

  state                    window title, row count, phase, summary line
  table [n]                dump the first n rows (default 10) as TSV
  headers                  column names with their indices
  set <attr> <text>        type into a QLineEdit, e.g. set subnet_edit 10.0.0.1-4
  check <attr> <0|1>       tick/untick a QCheckBox, e.g. check live_only 1
  pick <attr> <text>       choose a QComboBox entry, e.g. pick status_filter Ready
  click <attr>             press a QPushButton, e.g. click load_subnet_btn
  click-modal <attr> <nm>  press a button that opens a modal; screenshot it as
                           <nm>, then close it (use for Settings/Credentials and
                           for any button that may raise an error dialog)
  feed <row> <json>        render a fake scan result into <row>. THE important
                           one on Linux: real scans can only ever produce
                           Offline here, so this is the only way to see a
                           populated/coloured table. Keys are whatever
                           worker.py emits, e.g.
                           {"computer_name":"PC-1","ping":true,"wmi_ok":true,
                            "domain":"corp.local","last_patch":"2026-08-01T00:00:00+00:00"}
  wait <seconds>           pump the event loop for N seconds
  wait-scan [seconds]      block until the scan worker finishes (default 60)
  sorting <0|1>            turn table sorting on/off (feed forces it off)
  sort <col>               sort by a column index, e.g. sort 1 for IP
  shot <name>              screenshot the main window to shots/<name>.png
  eval <python>            escape hatch; `w` is the MainWindow, `app` the QApplication
  quit                     close cleanly (EOF does this too)
"""
import json
import os
import queue
import sys
import threading
import time

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.abspath(os.path.join(HERE, "..", "..", ".."))
sys.path.insert(0, REPO)

# Keep the app's settings/history out of the real profile.
os.environ.setdefault("LOCALAPPDATA", os.path.join(REPO, ".run-tmp"))
SHOTS = os.environ.get("SHOTS_DIR", os.path.join(REPO, "shots"))
os.makedirs(SHOTS, exist_ok=True)

from PyQt5.QtCore import QTimer  # noqa: E402
from PyQt5.QtWidgets import QApplication  # noqa: E402

from dhcp_inspector.main_window import MainWindow  # noqa: E402

app = QApplication(sys.argv)
w = MainWindow()
w.show()
w.raise_()

commands: "queue.Queue[str]" = queue.Queue()


def _read_stdin():
    for line in sys.stdin:
        commands.put(line.rstrip("\n"))
    commands.put("quit")  # EOF in batch mode


threading.Thread(target=_read_stdin, daemon=True).start()


def out(*parts):
    print(*parts, flush=True)


def _widget(attr):
    target = getattr(w, attr, None)
    if target is None:
        raise AttributeError(
            f"MainWindow has no {attr!r}. Try: eval [a for a in dir(w) if not a.startswith('_')]"
        )
    return target


def _pump(seconds):
    deadline = time.time() + seconds
    while time.time() < deadline:
        app.processEvents()
        time.sleep(0.02)


def _status_col():
    from dhcp_inspector.main_window import _STATUS_COL
    return _STATUS_COL


def _shot(name, widget=None):
    app.processEvents()
    pix = (widget or w).grab()
    path = os.path.join(SHOTS, f"{name}.png")
    pix.save(path)
    out(f"saved {path} ({pix.width()}x{pix.height()})")


def cmd_state(_):
    out(f"title={w.windowTitle()!r}")
    out(f"rows={w.table.rowCount()} phase={w.phase_label.text()!r}")
    out(f"progress={w.progress.value()}/{w.progress.maximum()}")
    out(f"summary={w.summary_label.text()!r}")
    worker = w._worker
    out(f"scanning={bool(worker and worker.isRunning())}")


def cmd_headers(_):
    names = [w.table.horizontalHeaderItem(i).text() for i in range(w.table.columnCount())]
    out(" ".join(f"{i}:{n}" for i, n in enumerate(names)))


def cmd_table(arg):
    limit = int(arg) if arg.strip() else 10
    cols = w.table.columnCount()
    for row in range(min(limit, w.table.rowCount())):
        cells = []
        for col in range(cols):
            item = w.table.item(row, col)
            cells.append(item.text() if item else "")
        hidden = " [hidden]" if w.table.isRowHidden(row) else ""
        out("\t".join(cells) + hidden)


def cmd_set(arg):
    attr, _, text = arg.partition(" ")
    _widget(attr).setText(text)
    out(f"{attr} = {text!r}")


def cmd_check(arg):
    attr, _, value = arg.partition(" ")
    _widget(attr).setChecked(value.strip() not in ("0", "false", ""))
    out(f"{attr} checked={_widget(attr).isChecked()}")


def cmd_pick(arg):
    attr, _, text = arg.partition(" ")
    _widget(attr).setCurrentText(text.strip())
    out(f"{attr} = {_widget(attr).currentText()!r}")


def cmd_click(arg):
    attr = arg.strip()
    _widget(attr).click()
    app.processEvents()
    out(f"clicked {attr}")


def cmd_click_modal(arg):
    attr, _, name = arg.partition(" ")
    name = name.strip() or attr
    # The dialog runs its own nested event loop, so the screenshot has to
    # happen from a timer that fires inside it.
    def grab():
        dlg = app.activeModalWidget()
        if dlg is None:
            out("no modal appeared")
            return
        out(f"modal={dlg.windowTitle()!r}")
        for label in dlg.findChildren(type(w.summary_label)):
            if label.text().strip():
                out(f"  text: {label.text()}")
        _shot(name, dlg)
        dlg.close()

    QTimer.singleShot(500, grab)
    _widget(attr).click()
    app.processEvents()
    out(f"clicked {attr}")


def cmd_feed(arg):
    row_text, _, payload = arg.partition(" ")
    row = int(row_text)
    result = json.loads(payload)
    result.setdefault("computer_name", f"row{row}")
    # on_row_ready fills a row cell by cell, and row indices are positional.
    # With sorting live, each write re-sorts the table and the next cell (or
    # the next feed) lands on whatever row slid into that index. The app's own
    # _start_scan turns sorting off for the whole scan for exactly this
    # reason, so feed does the same and leaves it off. Re-enable deliberately
    # with `sorting 1` when you want to exercise sort behaviour.
    w.table.setSortingEnabled(False)
    w.on_row_ready(row, result)
    app.processEvents()
    status = w.table.item(row, _status_col())
    out(f"row {row} -> status={status.text()!r} bg={status.background().color().name()}")


def cmd_wait(arg):
    _pump(float(arg.strip() or 1))
    out("waited")


def cmd_wait_scan(arg):
    deadline = time.time() + float(arg.strip() or 60)
    while time.time() < deadline:
        app.processEvents()
        worker = w._worker
        if worker is None or not worker.isRunning():
            _pump(0.3)  # let the final signals land
            out(f"scan finished, phase={w.phase_label.text()!r}")
            return
        time.sleep(0.05)
    out("TIMEOUT waiting for scan")


def cmd_sorting(arg):
    on = arg.strip() not in ("0", "false", "")
    w.table.setSortingEnabled(on)
    app.processEvents()
    out(f"sorting={on} (enabling re-sorts the table immediately)")


def cmd_sort(arg):
    col = int(arg.strip())
    w.table.sortItems(col)
    app.processEvents()
    out(f"sorted by column {col}")


def cmd_shot(arg):
    _shot(arg.strip() or "shot")


def cmd_eval(arg):
    out(repr(eval(arg, {"w": w, "app": app, "json": json})))


HANDLERS = {
    "state": cmd_state, "headers": cmd_headers, "table": cmd_table,
    "set": cmd_set, "check": cmd_check, "pick": cmd_pick,
    "click": cmd_click, "click-modal": cmd_click_modal,
    "feed": cmd_feed, "wait": cmd_wait, "wait-scan": cmd_wait_scan,
    "sorting": cmd_sorting, "sort": cmd_sort,
    "shot": cmd_shot, "eval": cmd_eval,
}


def poll():
    try:
        line = commands.get_nowait()
    except queue.Empty:
        return
    line = line.strip()
    if not line or line.startswith("#"):
        return
    if line == "quit":
        out("bye")
        app.quit()
        return
    verb, _, arg = line.partition(" ")
    out(f"> {line}")
    handler = HANDLERS.get(verb)
    if handler is None:
        out(f"ERR unknown command {verb!r}; known: {' '.join(sorted(HANDLERS))}")
        return
    try:
        handler(arg)
        out("OK")
    except Exception as exc:
        import traceback
        traceback.print_exc()
        out(f"ERR {type(exc).__name__}: {exc}")


timer = QTimer()
timer.timeout.connect(poll)
timer.start(50)

out("ready")
sys.exit(app.exec_())
