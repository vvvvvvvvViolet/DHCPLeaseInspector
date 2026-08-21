---
name: run-dhcp-lease-inspector
description: Build, run, and drive the DHCP Lease Inspector PyQt5 desktop app. Use when asked to start or launch the app, take a screenshot of its window, click through its UI, verify a table/status/colour change, or smoke-test its scanning logic.
---

A PyQt5 desktop GUI that audits Windows domain computers (AD lookup, ping
sweep, WMI over DCOM, subnet scan). It targets Windows, but it **does launch
and render on headless Linux** — drive it via
`.claude/skills/run-dhcp-lease-inspector/driver.py`, a stdin-command REPL that
runs the real window under `xvfb-run` and saves PNGs.

All paths below are relative to the repo root.

**The one thing to know before you start:** every Windows-only path (AD, WMI,
`nbtstat`, DHCP leases) fails in this container, so a *real* scan here can only
ever produce `Offline` rows. To see a populated, colour-coded table — the thing
most UI changes affect — use the driver's `feed` command, which pushes a fake
result dict through the real render path. See [Run: fake data](#run-fake-data).

## Prerequisites

Qt's `xcb` platform plugin needs these; without them the app aborts with
"Could not load the Qt platform plugin xcb".

```bash
apt-get update
apt-get install -y xvfb libxcb-icccm4 libxcb-image0 libxcb-keysyms1 \
  libxcb-render-util0 libxcb-shape0 libxcb-xinerama0 libxcb-xkb1 \
  libxkbcommon-x11-0
```

## Setup

```bash
pip install -r requirements.txt    # PyQt5, openpyxl
```

The app writes settings/history to `%LOCALAPPDATA%`. The driver defaults it to
`./.run-tmp/` so runs stay isolated — `rm -rf .run-tmp` resets to factory
settings. Screenshots go to `./shots/` (override with `SHOTS_DIR`).

## Run: agent path (the driver)

Pipe commands in; each one echoes its result then `OK` or `ERR …`.

```bash
printf '%s\n' \
  'state' \
  'headers' \
  'set subnet_edit 10.20.30.1-4' \
  'click load_subnet_btn' \
  'table 4' \
  'click check_status_btn' \
  'wait-scan 60' \
  'state' \
  'shot 01-scan' \
  'quit' \
| xvfb-run -a --server-args="-screen 0 1400x900x24" \
    python3 -u .claude/skills/run-dhcp-lease-inspector/driver.py
```

Verified output ends with `Total 4 | … | Offline 4` and
`saved …/shots/01-scan.png (1180x620)`. **Open the PNG and look at it** — a
blank frame means the window never mapped.

Commands: `state`, `headers`, `table [n]`, `set <attr> <text>`,
`check <attr> <0|1>`, `pick <attr> <text>`, `click <attr>`,
`click-modal <attr> <name>`, `feed <row> <json>`, `wait <s>`, `wait-scan [s]`,
`sorting <0|1>`, `sort <col>`, `shot <name>`, `eval <python>`, `quit`.
`<attr>` is a `MainWindow` attribute — `eval [a for a in dir(w) if a.endswith('_btn')]`
lists the buttons.

**Dialogs need `click-modal`, not `click`.** Settings, Credentials and every
error box run a nested event loop that blocks the driver forever. `click-modal`
schedules the screenshot from inside that loop, prints the dialog's labels, then
closes it:

```bash
printf '%s\n' \
  'click-modal settings_btn 02-settings' \
  'click-modal credentials_btn 03-credentials' \
  'click-modal load_ad_btn 04-load-ad-error' \
  'quit' \
| xvfb-run -a --server-args="-screen 0 1400x900x24" \
    python3 -u .claude/skills/run-dhcp-lease-inspector/driver.py
```

`load_ad_btn` is a useful smoke test of the error path: it prints
`modal='Load AD failed'` / `[Errno 2] No such file or directory: 'powershell'`
and the app stays usable.

<a id="run-fake-data"></a>
## Run: fake data (how to actually see the UI)

`feed <row> <json>` calls `MainWindow.on_row_ready` with a result dict shaped
like the one `worker.py` emits, exercising status derivation, colouring,
tooltips and the summary counters — none of which a Linux scan can reach.

```bash
python3 - > /tmp/cmds.txt <<'PY'
import json
from datetime import datetime, timedelta, timezone
now = datetime.now(timezone.utc); iso = lambda d: (now - timedelta(days=d)).isoformat()
rows = [
 {"computer_name":"A-C14-PROV","ip":"10.20.30.1","ping":True,"wmi_ok":True,"part_of_domain":True,
  "domain":"corp.local","dhcp_server":"10.20.30.254","os_version":"Windows 11 Pro",
  "last_boot":iso(2),"last_patch":iso(5),"recent_hotfixes":"KB5031354 (2026-08-16)",
  "ad_password_last_set":iso(3),"ad_last_logon":iso(1),"in_ad":True},                   # Ready
 {"computer_name":"V-D35-MMI","ip":"10.20.30.2","ping":True,"wmi_ok":True,
  "last_patch":iso(300),"ad_password_last_set":iso(2),"in_ad":True},                    # Patch Overdue
 {"computer_name":"OLD-PC","ip":"10.20.30.3","ping":True,"wmi_ok":True,
  "ad_domain":"corp.local","ad_password_last_set":iso(400),"in_ad":True},               # Domain Issue
 {"computer_name":"PRINTER-2","ip":"10.20.30.4","ping":True,"wmi_ok":False,
  "lease_mac":"00-11-22-33-44-55","in_ad":False},                                       # Not in AD
]
print("set subnet_edit 10.20.30.1-4"); print("click load_subnet_btn")
for i, r in enumerate(rows): print(f"feed {i} {json.dumps(r)}")
print("table 4"); print("shot 05-populated"); print("quit")
PY

xvfb-run -a --server-args="-screen 0 1400x900x24" \
  python3 -u .claude/skills/run-dhcp-lease-inspector/driver.py < /tmp/cmds.txt
```

Verified: rows come back `Ready` (`#c8e6c9` green), `Patch Overdue` and
`Domain Issue` (`#fff9c4` yellow, the latter labelled `corp.local (Stale)`), and
`Not in AD`; the summary reads `Total 4 | Ready 1 | Domain Issue 1 | Patch
Overdue 1 | Not in AD 1`.

## Run: direct invocation (no GUI)

Most changes land in `scoring.py`, `subnet.py` or `checks.py`, which are pure
functions — import and call them, no Qt, no xvfb:

```bash
LOCALAPPDATA=$PWD/.run-tmp python3 -c "
from datetime import datetime, timedelta, timezone
from dhcp_inspector import scoring, subnet, checks
now = datetime.now(timezone.utc); iso = lambda d: (now - timedelta(days=d)).isoformat()
print(subnet.parse_targets('10.20.30.0/30'))                          # ['10.20.30.1', '10.20.30.2']
print(scoring.compute_status({'ping':True,'last_patch':iso(300)}))    # Patch Overdue
print(scoring.domain_label({'ad_domain':'corp.local','ad_password_last_set':iso(400)}))
print(checks._NBT_NAME.search('  A-C14-PROV  <00>  UNIQUE  Registered').group(1))
"
```

Patch the Windows boundary with `unittest.mock.patch` to test the rest:
`checks.resolve_and_ping`, `checks.check_computer`, `ad_utils.load_ad_computers`,
`dhcp_leases.load_leases`, and `checks._ping` / `checks.netbios_name` are the
seams.

## Run: human path

`python main.py` opens the window and blocks. Useless headless — under
`xvfb-run` you get a window nobody can see or screenshot. Use the driver.

## Test

There is no test suite in this repo (no `tests/`, and CI only builds the
`.exe`). The driver and the direct-invocation snippet above are the smoke
tests.

## Gotchas

- **`feed` must run with table sorting off, and leaves it off.** `on_row_ready`
  fills a row cell by cell and row indices are positional. With sorting live,
  writing the Computer cell makes Qt re-sort *immediately*, so the remaining
  cells — and the next `feed` — land on whatever row slid into that index. The
  observed symptom is a scrambled table (Computer `10.20.30.2` next to IP
  `10.20.30.1`). The app dodges this because `_start_scan` disables sorting for
  the whole scan; the driver mirrors that. Re-enable deliberately with
  `sorting 1`. **Any new code path that calls `on_row_ready` outside a scan
  needs the same guard.**
- **`click` on a button that opens a dialog hangs the driver forever** — the
  modal's nested event loop never returns to the command poller. Use
  `click-modal`. This includes buttons that only *might* raise an error dialog
  (`load_ad_btn`, `load_subnet_btn` with a too-large range).
- **A real scan on Linux always yields `Offline`.** There is no `ping` binary in
  this container, so `checks._ping` returns False for every host, phase 2 (WMI)
  is skipped entirely, and no host is ever named. This is correct behaviour, not
  a failure — but it means a real scan can't validate any rendering change.
- **The window is 1180x620 regardless of the X screen size**, since `grab()`
  captures the widget, not the screen. Making the Xvfb screen bigger doesn't
  show more rows; `eval w.resize(1600, 900)` does.
- **`shot` after `quit` produces nothing** — the app has already exited. Put
  `shot` before `quit` in the command list.
- **Ephemeral containers re-clone at an older commit.** If GUI attributes the
  driver references are missing (`AttributeError: 'MainWindow' object has no
  attribute 'subnet_edit'`), the checkout is behind the remote, not broken:
  `git fetch origin <branch> && git merge --ff-only origin/<branch>`.

## Troubleshooting

| Symptom | Fix |
|---|---|
| `Could not load the Qt platform plugin "xcb" … Aborted` | Install the `libxcb-*` packages in Prerequisites. Confirm with `ldd $(python3 -c "import PyQt5,os;print(os.path.dirname(PyQt5.__file__))")/Qt5/plugins/platforms/libqxcb.so \| grep "not found"` — it must print nothing. |
| `ModuleNotFoundError: No module named 'PyQt5'` | `pip install -r requirements.txt`; the container was recycled. |
| Driver prints nothing, then the command times out | You used `click` on a dialog button. Use `click-modal`. |
| No output at all from a piped run that timed out | Buffering. Always run the driver with `python3 -u`. |
| `ERR AttributeError: MainWindow has no 'x'` | `eval [a for a in dir(w) if not a.startswith('_')]` to list real attributes. |
| Rows show the wrong values after `feed` | Sorting was re-enabled between feeds — see Gotchas. |
| `QStandardPaths: XDG_RUNTIME_DIR not set` | Harmless noise on stderr; ignore. |
