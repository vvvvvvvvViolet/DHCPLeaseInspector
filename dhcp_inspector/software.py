"""Installed-software inventory, read from the remote registry over DCOM.

Reads the same Uninstall keys that "Programs and Features" lists, through
the StdRegProv WMI class on the existing DCOM session. Deliberately NOT
Win32_Product: querying that class makes Windows Installer run a
consistency check — and potentially a repair — on every MSI product on the
target, which is slow and has side effects on the machine being audited.
"""
import json
import subprocess

from . import config
from .checks import _SESSION_PREAMBLE, _credential_env
from .process_utils import run_powershell

_SOFTWARE_SCRIPT = r"""
$result = [ordered]@{
    ComputerName = $ComputerName
    Ok = $false
    Partial = $false
    Software = @()
    FirstError = $null
}
""" + _SESSION_PREAMBLE + r"""
$HKLM = [uint32]2147483650
$HKU  = [uint32]2147483651

# Each registry value is its own WMI call, hundreds per machine. If the link
# drops mid-scan every remaining call would wait out its full timeout, so
# give up after a run of consecutive failures and report what we have.
$script:failures = 0

function Invoke-Reg($method, $arguments) {
    if ($script:failures -ge 5) { return $null }
    try {
        $r = Invoke-CimMethod -CimSession $session -Namespace 'root\default' -ClassName StdRegProv `
            -MethodName $method -Arguments $arguments -OperationTimeoutSec 15 -ErrorAction Stop
        $script:failures = 0
        return $r
    } catch {
        $script:failures++
        Note-Error $_
        return $null
    }
}

function Get-SubKeys($hive, $path) {
    $r = Invoke-Reg 'EnumKey' @{ hDefKey = $hive; sSubKeyName = $path }
    if ($r -and $r.ReturnValue -eq 0 -and $r.sNames) { return $r.sNames }
}

# A missing value is ReturnValue 1, not an exception — normal, not a failure.
function Get-String($hive, $key, $name) {
    $r = Invoke-Reg 'GetStringValue' @{ hDefKey = $hive; sSubKeyName = $key; sValueName = $name }
    if ($r -and $r.ReturnValue -eq 0) { return $r.sValue }
    return $null
}

function Get-Dword($hive, $key, $name) {
    $r = Invoke-Reg 'GetDWORDValue' @{ hDefKey = $hive; sSubKeyName = $key; sValueName = $name }
    if ($r -and $r.ReturnValue -eq 0) { return [int64]$r.uValue }
    return $null
}

if ($session) {
    $machineKey = 'SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall'
    $probe = Invoke-Reg 'EnumKey' @{ hDefKey = $HKLM; sSubKeyName = $machineKey }
    if ($probe -and $probe.ReturnValue -eq 0) {
        $result.Ok = $true
    } elseif ($probe) {
        $result.FirstError = "Registry read refused (StdRegProv code $($probe.ReturnValue))"
    }

    if ($result.Ok) {
        $sources = New-Object System.Collections.ArrayList
        [void]$sources.Add(@{ Hive = $HKLM; Path = $machineKey; Scope = 'Machine' })
        [void]$sources.Add(@{ Hive = $HKLM; Path = 'SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall'; Scope = 'Machine (32-bit)' })
        # Per-user installs (Teams, Zoom, some browsers) live in each user's
        # hive. Only hives of users currently signed in are loaded, so this
        # sees signed-in users' per-user apps and nobody else's.
        foreach ($sid in (Get-SubKeys $HKU '')) {
            if ($sid -match '^S-1-5-21-[\d-]+$') {
                [void]$sources.Add(@{ Hive = $HKU; Path = "$sid\Software\Microsoft\Windows\CurrentVersion\Uninstall"; Scope = 'Per-user' })
            }
        }

        $apps = New-Object System.Collections.ArrayList
        foreach ($src in $sources) {
            foreach ($sub in (Get-SubKeys $src.Hive $src.Path)) {
                $key = "$($src.Path)\$sub"
                $name = Get-String $src.Hive $key 'DisplayName'
                if (-not $name) { continue }
                # Programs and Features hides system components and child
                # update entries; match it so the list reads the same.
                if ((Get-Dword $src.Hive $key 'SystemComponent') -eq 1) { continue }
                if (Get-String $src.Hive $key 'ParentKeyName') { continue }
                [void]$apps.Add([ordered]@{
                    Name        = $name.Trim()
                    Version     = (Get-String $src.Hive $key 'DisplayVersion')
                    Publisher   = (Get-String $src.Hive $key 'Publisher')
                    InstallDate = (Get-String $src.Hive $key 'InstallDate')
                    Scope       = $src.Scope
                })
            }
        }
        $result.Software = $apps
        $result.Partial = ($script:failures -ge 5)
    }

    Remove-CimSession $session -ErrorAction SilentlyContinue
}

# -Depth matters: the default of 2 would flatten each app record to the
# string "System.Collections.Specialized.OrderedDictionary".
$result | ConvertTo-Json -Compress -Depth 4
"""


def _build_script(computer_name: str) -> str:
    # Same single-quoted literal embedding as checks._build_script.
    escaped = computer_name.replace("'", "''")
    return f"$ComputerName = '{escaped}'\n" + _SOFTWARE_SCRIPT


def _format_install_date(raw) -> str:
    """Registry InstallDate is conventionally YYYYMMDD; show it as a date."""
    text = str(raw or "").strip()
    if len(text) == 8 and text.isdigit():
        return f"{text[:4]}-{text[4:6]}-{text[6:]}"
    return text


def _clean(value) -> str:
    return str(value).strip() if value is not None else ""


def _normalise(entries) -> list[dict]:
    if isinstance(entries, dict):  # a single app may not arrive as a list
        entries = [entries]
    apps, seen = [], set()
    for entry in entries or []:
        if not isinstance(entry, dict):
            continue
        app = {
            "name": _clean(entry.get("Name")),
            "version": _clean(entry.get("Version")),
            "publisher": _clean(entry.get("Publisher")),
            "install_date": _format_install_date(entry.get("InstallDate")),
            "scope": _clean(entry.get("Scope")),
        }
        if not app["name"]:
            continue
        # Some installers register under both registry views; one row each.
        identity = (app["name"].casefold(), app["version"], app["publisher"].casefold())
        if identity in seen:
            continue
        seen.add(identity)
        apps.append(app)
    apps.sort(key=lambda a: (a["name"].casefold(), a["version"]))
    return apps


def _failed(computer_name: str, error: str) -> dict:
    return {"computer": computer_name, "ok": False, "partial": False, "apps": [], "error": error}


def list_software(
    computer_name: str,
    credential: tuple[str, str] | None = None,
    timeout: float | None = None,
) -> dict:
    """Inventory one computer's installed software.

    Returns {"computer", "ok", "partial", "apps": [{name, version, publisher,
    install_date, scope}], "error"}. "partial" means the connection failed
    mid-read and the list is incomplete. Never raises.
    """
    if timeout is None:
        timeout = float(config.get_settings().software_timeout_s)
    try:
        result = run_powershell(
            _build_script(computer_name),
            timeout=timeout,
            env=_credential_env(credential),
        )
    except subprocess.TimeoutExpired:
        return _failed(computer_name, f"Timed out after {timeout:.0f}s")
    except OSError as exc:
        return _failed(computer_name, str(exc))

    if result.returncode != 0 or not (result.stdout or "").strip():
        return _failed(computer_name, (result.stderr or "").strip() or "No response")

    try:
        data = json.loads(result.stdout.strip())
    except ValueError:
        return _failed(computer_name, "Unexpected output from software script")

    ok = bool(data.get("Ok"))
    return {
        "computer": computer_name,
        "ok": ok,
        "partial": bool(data.get("Partial")),
        "apps": _normalise(data.get("Software")) if ok else [],
        # A per-value hiccup on a machine that otherwise answered is noise.
        "error": None if ok and not data.get("Partial") else data.get("FirstError"),
    }
