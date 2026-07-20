# DHCP Lease Inspector

Windows GUI utility (Python + Tkinter) for checking a machine's domain/DHCP
health at a glance:

- **Domain / OS** — whether the machine is joined to a domain (and which
  domain/workgroup), plus OS name, version, build, and architecture.
- **DHCP Lease** — parses `ipconfig /all` to show the active DHCP lease per
  network adapter (IP, subnet mask, DHCP server, lease obtained/expires).
- **Scan DHCP Servers** — broadcasts a DHCPDISCOVER on the local network and
  lists every DHCP server that responds (useful for spotting rogue DHCP
  servers). Requires an elevated (Administrator) prompt, since UDP port 68
  is normally owned by the Windows DHCP Client service.
- **DHCP Client Service** — reports the status/start type of the Windows
  `Dhcp` service.

## Requirements

- Windows (uses `ipconfig`, `sc`/PowerShell `Get-Service`, and WMI/CIM)
- Python 3.10+ (standard library only, no extra packages required)

## Run

```
python main.py
```

For the "Scan DHCP Servers" tab, run from an elevated command prompt /
PowerShell (Run as Administrator).

## Build a standalone .exe

PyInstaller must run on Windows (it does not cross-compile), so pick one:

**Option A — build locally on Windows:**

```
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
  system_info.py    # domain join status + OS version (CIM/WMI via PowerShell)
  dhcp_lease.py      # active DHCP lease per adapter (ipconfig /all)
  dhcp_scan.py       # DHCPDISCOVER broadcast + offer collection
  client_status.py   # Windows "Dhcp" service status
  gui.py             # Tkinter GUI wiring the above together
```
