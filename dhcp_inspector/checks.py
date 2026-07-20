"""Runs the combined per-computer health check (ping, domain, DHCP, WSUS, OS)."""
import json
import subprocess

from .process_utils import run_hidden

# WMI queries run even when ping fails: many networks block ICMP while WMI
# still works, so ping alone must not decide "offline". FirstError keeps the
# first WMI failure message (e.g. Access Denied) so the UI can distinguish
# "no rights" from "machine down".
_CHECK_SCRIPT = r"""
param($ComputerName)
$result = [ordered]@{
    ComputerName = $ComputerName
    Ping = $false
    WmiOk = $false
    PartOfDomain = $null
    Domain = $null
    DHCPServer = $null
    OSVersion = $null
    LastBoot = $null
    WSUS = $null
    FirstError = $null
}

function Note-Error($err) {
    if ($null -eq $result.FirstError) {
        $result.FirstError = ($err | Out-String).Trim()
    }
}

try {
    $result.Ping = [bool](Test-Connection -ComputerName $ComputerName -Count 1 -Quiet -ErrorAction Stop)
} catch {
    $result.Ping = $false
}

try {
    $cs = Get-CimInstance -ComputerName $ComputerName -ClassName Win32_ComputerSystem -ErrorAction Stop
    $result.WmiOk = $true
    $result.PartOfDomain = [bool]$cs.PartOfDomain
    $result.Domain = $cs.Domain
} catch { Note-Error $_ }

if ($result.Ping -or $result.WmiOk) {
    try {
        $os = Get-CimInstance -ComputerName $ComputerName -ClassName Win32_OperatingSystem -ErrorAction Stop
        $result.WmiOk = $true
        $result.OSVersion = $os.Caption
        $result.LastBoot = $os.LastBootUpTime.ToString("o")
    } catch { Note-Error $_ }

    try {
        $nic = Get-CimInstance -ComputerName $ComputerName -ClassName Win32_NetworkAdapterConfiguration `
            -Filter "IPEnabled=True AND DHCPEnabled=True" -ErrorAction Stop | Select-Object -First 1
        $result.DHCPServer = $nic.DHCPServer
    } catch { Note-Error $_ }

    try {
        $regProv = Get-CimInstance -ComputerName $ComputerName -Namespace 'root\default' -ClassName StdRegProv -ErrorAction Stop
        $val = Invoke-CimMethod -InputObject $regProv -MethodName GetStringValue -Arguments @{
            hDefKey     = 2147483650
            sSubKeyName = "SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate"
            sValueName  = "WUServer"
        } -ErrorAction Stop
        $result.WSUS = $val.sValue
    } catch { Note-Error $_ }
}

$result | ConvertTo-Json -Compress
"""


def _failed_result(computer_name: str, error: str) -> dict:
    return {
        "computer_name": computer_name,
        "ping": False,
        "wmi_ok": False,
        "part_of_domain": None,
        "domain": None,
        "dhcp_server": None,
        "os_version": None,
        "last_boot": None,
        "wsus": None,
        "error": error,
    }


def check_computer(computer_name: str, timeout: float = 60.0) -> dict:
    """Runs every check for a single computer in one PowerShell round-trip.

    Never raises: timeouts and PowerShell failures come back as a result
    dict with the "error" field set, so a bad machine can't abort a scan.
    """
    try:
        result = run_hidden(
            [
                "powershell", "-NoProfile", "-NonInteractive", "-Command", _CHECK_SCRIPT,
                "-ComputerName", computer_name,
            ],
            timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        return _failed_result(computer_name, f"Timed out after {timeout:.0f}s")
    except OSError as exc:
        return _failed_result(computer_name, str(exc))

    if result.returncode != 0 or not result.stdout.strip():
        return _failed_result(computer_name, result.stderr.strip() or "No response")

    try:
        data = json.loads(result.stdout.strip())
    except ValueError:
        return _failed_result(computer_name, "Unexpected output from check script")

    wmi_ok = bool(data.get("WmiOk"))
    return {
        "computer_name": data.get("ComputerName", computer_name),
        "ping": bool(data.get("Ping")),
        "wmi_ok": wmi_ok,
        "part_of_domain": data.get("PartOfDomain"),
        "domain": data.get("Domain"),
        "dhcp_server": data.get("DHCPServer"),
        "os_version": data.get("OSVersion"),
        "last_boot": data.get("LastBoot"),
        "wsus": data.get("WSUS"),
        # Surface the WMI error only when nothing succeeded — a machine that
        # answered WMI but denied one sub-query is still a usable result.
        "error": None if wmi_ok else data.get("FirstError"),
    }
