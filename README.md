# DHCP Lease Inspector

Windows GUI utility (PyQt5) for auditing domain computers in one click.
Single-page UI with three buttons:

- **Load AD** — pulls the computer list from Active Directory
  (`Get-ADComputer`; requires the RSAT ActiveDirectory PowerShell module).
  An optional name filter narrows the query (substring match) before it
  hits a big domain.
- **Check Status** — runs every check below for all loaded computers on a
  background `QThread` with up to 15 machines scanned in parallel, so the
  UI never freezes and large fleets finish quickly. A progress bar tracks
  the scan and a **Cancel** button stops it mid-flight. Results fill in
  row by row as they come back:
  - **Ping** — reachability
  - **Domain** — domain join status / domain name
  - **DHCP Server** — the DHCP server that leased the machine's active IP
  - **WSUS** — configured WSUS server (from `WUServer` policy), if any
  - **OS Version** — OS caption
  - **Uptime** — time since last boot
  - **Score / Status** — composite readiness score (0-100) and a
    `Ready` / `Needs Attention` / `Offline` label
- **Export Excel** — saves the table to an `.xlsx` report, following the
  on-screen sort order and status filter, with rows colored by status.

Rows are color-coded (green = Ready, yellow = Needs Attention,
red = Offline/Error), every column is click-to-sort, and a **Show**
dropdown filters the table to one status. Hovering a failed row shows the
underlying error (e.g. Access Denied vs timeout) as a tooltip.

All remote queries go through WMI over **DCOM** (a CIM session with
`-Protocol Dcom`), not WS-Man/WinRM, so no `winrm quickconfig` / PSRemoting
setup is required on the target machines — just DCOM/WMI reachability
(firewall) and admin rights. Each call has a 15-second operation timeout so
offline machines fail fast. Every PowerShell/cmd call runs with its console
window hidden (`CREATE_NO_WINDOW`), so nothing flashes on screen while
scanning.

## Requirements

- Windows, domain-joined, with the RSAT **Active Directory** PowerShell
  module installed for "Load AD"
- Python 3.10+
- `pip install -r requirements.txt` (PyQt5, openpyxl)

## Run

```
pip install -r requirements.txt
python main.py
```

## Build a standalone .exe

PyInstaller must run on Windows (it does not cross-compile), so pick one:

**Option A — build locally on Windows:**

```
pip install -r requirements.txt
pip install -r requirements-dev.txt
pyinstaller --onefile --windowed --name DHCPLeaseInspector main.py
```

The executable is created at `dist\DHCPLeaseInspector.exe`.

**Option B — build via GitHub Actions (no Windows machine needed):**

Every push to `main` or a `claude/**` branch triggers the
`Build Windows EXE` workflow (`.github/workflows/build-exe.yml`), which
builds on a `windows-latest` runner. You can also trigger it manually from
the Actions tab ("Run workflow"). Download the built `.exe` from the run's
**Artifacts** section (`DHCPLeaseInspector-exe`).

## Project layout

```
main.py                        # entry point
dhcp_inspector/
  ad_utils.py         # Get-ADComputer via PowerShell
  checks.py           # combined per-computer check (ping/domain/DHCP/WSUS/OS/uptime)
  scoring.py           # uptime formatting + readiness score/status
  export_excel.py      # writes the results table to .xlsx
  process_utils.py     # subprocess helper that hides the console window
  worker.py             # QThread that runs checks off the GUI thread
  main_window.py        # PyQt5 single-page window (Load AD / Check Status / Export Excel)
```
