# DHCP Lease Inspector

Windows GUI utility (PyQt5) for auditing domain computers in one click.
Single-page UI with three buttons:

- **Load AD** — pulls the computer list from Active Directory
  (`Get-ADComputer`; requires the RSAT ActiveDirectory PowerShell module),
  along with each machine's domain, AD-recorded OS, account-enabled flag,
  computer-account password age, and last logon time. The **Domain**,
  **OS Version**, and **Last Logon** columns are filled from this AD data
  immediately — even before a live scan and even for machines that can't
  be reached over the network. An optional name filter narrows the query
  (substring match) before it hits a big domain.
- **Load Subnet** — scans an IP range instead of the AD list: accepts CIDRs
  (`10.20.30.0/24`), ranges (`10.20.30.10-50` or the full form), and single
  addresses, comma- or space-separated. Live addresses are named by reverse
  DNS, and if AD was loaded first each host is matched back to its computer
  account — anything answering without one is flagged **Not in AD**, which
  is how unmanaged or rogue devices surface. A **Live hosts only** checkbox
  hides the addresses that never answered (a /24 is mostly empty), and the
  range size is capped (default 4096) so a stray `/8` can't be expanded.
- **Check Status** — scans all loaded computers on a background `QThread`
  in **two phases**: first a fast DNS + ping sweep (60 machines in
  parallel; a dead machine costs ~2 s), then WMI checks only for the
  machines that answered ping (15 in parallel), so a mostly-dead fleet of
  thousands finishes in minutes instead of hours. A progress bar shows the
  current phase, and **Cancel** stops the scan mid-flight. Columns:
  - **IP / Ping** — the DNS-resolved address and ping result. A name with
    no DNS record shows `No DNS` — a machine that likely no longer exists —
    which is distinct from `Fail` (resolves but doesn't answer).
  - **Domain** — domain name plus a health note. The domain check is
    AD-based (works without touching the machine): a machine whose
    computer-account password is older than the stale threshold shows
    `(Stale)` and a disabled account shows `(Disabled)` — both strong
    signals the machine has fallen off the domain. A live WMI result
    showing the machine isn't joined shows `Not Joined`.
  - **DHCP Server** — the DHCP server that leased the machine's active IP
  - **OS Version** — live OS caption, falling back to the AD-recorded OS
  - **Uptime** — time since last boot
  - **Last Logon** — the machine's last AD logon date (from the replicated
    `LastLogonTimestamp`, which can lag up to ~14 days) — separates
    "went offline yesterday" from "dead for months, decommission it"
  - **Last Patch** — the install date of the newest hotfix
    (`Win32_QuickFixEngineering`); the tooltip lists the most recent KB
    IDs. A machine whose newest patch is older than the overdue threshold
    is flagged `Patch Overdue`.
  - **Status** — `Ready` / `Domain Issue` / `Patch Overdue` / `Not in AD` /
    `Offline` / `Error` / `No DNS`
  - **Change** — what changed vs the previous scan, e.g. `Ready → Offline`
    or `New`. Each completed scan is saved (last 30 runs kept) in the
    per-user app-data folder, and the next scan compares against it.
- **Re-check Failed** — re-scans only the rows currently `Offline` /
  `Error` / `No DNS`, so a follow-up pass doesn't re-do the whole fleet.
- **Export Excel** — saves the table to an `.xlsx` report, following the
  on-screen sort order and status filter, with rows colored by status.
- **Credentials** — optionally run the WMI checks as a different account
  (e.g. a domain admin) instead of the user who launched the app. This is
  usually what makes the DHCP / OS / Uptime columns populate: without
  local-admin rights on the target the WMI calls come back Access Denied.
  The username/password are held in memory for the session only — never
  written to settings, history, or the command line; they're passed to
  PowerShell through an environment variable and turned into a
  `PSCredential` for `New-CimSession`.
- **Settings** — stale-password and patch-overdue thresholds, the maximum
  subnet size, ping/WMI parallelism and timeouts, and whether to attempt
  WMI on ping-failed
  machines (off by default; turn on to find hosts that block ICMP but
  allow WMI). Saved to `%LOCALAPPDATA%\DHCPLeaseInspector\settings.json`.

A summary line above the table live-counts every status (Total / Ready /
Domain Issue / Patch Overdue / Not in AD / Offline / Error / No DNS). Rows are color-coded (green =
Ready, yellow = Domain Issue, red = Offline/Error/No DNS), every column is
click-to-sort, and a **Show** dropdown filters the table to one status.
Hovering a failed row shows the underlying error (e.g. Access Denied vs
timeout) as a tooltip.

All remote queries go through WMI over **DCOM** (a CIM session with
`-Protocol Dcom`), not WS-Man/WinRM, so no `winrm quickconfig` / PSRemoting
setup is required on the target machines — just DCOM/WMI reachability
(firewall) and admin rights (see **Credentials** above if the current user
lacks them). Each call has a 15-second operation timeout so offline
machines fail fast. Every PowerShell/cmd call runs with its console
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
  ad_utils.py         # Get-ADComputer: names + domain/OS/enabled/pwd age/last logon
  subnet.py            # expands CIDRs/ranges into the addresses to probe
  checks.py           # DNS/PTR+ping probe, and the WMI check over DCOM
  scoring.py           # uptime/last-logon formatting + AD domain health + status
  config.py            # user settings (thresholds, parallelism, timeouts)
  history.py           # saves each run so the next one can show what changed
  export_excel.py      # writes the results table to .xlsx
  process_utils.py     # subprocess helper that hides the console window
  worker.py             # QThread: ping sweep phase, then WMI phase, + AD merge
  main_window.py        # PyQt5 single-page window (Load AD / Check Status / Export Excel)
```
