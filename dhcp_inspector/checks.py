"""Runs the combined per-computer health check (ping, domain, DHCP, WSUS, OS)."""
import json
import subprocess

from .process_utils import run_hidden

# WMI queries run even when ping fails: many networks block ICMP while WMI
# still works, so ping alone must not decide "offline". FirstError keeps the
# first WMI failure message (e.g. Access Denied) so the UI can distinguish
# "no rights" from "machine down".
# The computer name is prepended as a $ComputerName assignment (see
# _build_command). We deliberately do NOT use `param(...)` + a trailing
# `-ComputerName` argument: with `powershell -Command "<script>"`, anything
# after the script string is treated as command text, not bound to param(),
# so $ComputerName would come back null and every machine would fail.
_CHECK_SCRIPT = r"""
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

# Query over DCOM, not the CIM default (WS-Man/WinRM): WinRM is rarely
# enabled on ordinary domain workstations, whereas DCOM/WMI works out of
# the box wherever the firewall allows it. -OperationTimeoutSec bounds each
# call so a dead or unreachable host fails fast instead of hanging on RPC.
$session = $null
try {
    $opt = New-CimSessionOption -Protocol Dcom
    $session = New-CimSession -ComputerName $ComputerName -SessionOption $opt -OperationTimeoutSec 15 -ErrorAction Stop
} catch { Note-Error $_ }

if ($session) {
    try {
        $cs = Get-CimInstance -CimSession $session -ClassName Win32_ComputerSystem -OperationTimeoutSec 15 -ErrorAction Stop
        $result.WmiOk = $true
        $result.PartOfDomain = [bool]$cs.PartOfDomain
        $result.Domain = $cs.Domain
    } catch { Note-Error $_ }

    # Only keep probing once the first WMI call proves the host answers, so a
    # dead machine costs one timed-out call, not four.
    if ($result.WmiOk) {
        try {
            $os = Get-CimInstance -CimSession $session -ClassName Win32_OperatingSystem -OperationTimeoutSec 15 -ErrorAction Stop
            $result.OSVersion = $os.Caption
            $result.LastBoot = $os.LastBootUpTime.ToString("o")
        } catch { Note-Error $_ }

        try {
            $nic = Get-CimInstance -CimSession $session -ClassName Win32_NetworkAdapterConfiguration `
                -Filter "IPEnabled=True AND DHCPEnabled=True" -OperationTimeoutSec 15 -ErrorAction Stop | Select-Object -First 1
            $result.DHCPServer = $nic.DHCPServer
        } catch { Note-Error $_ }

        try {
            $regProv = Get-CimInstance -CimSession $session -Namespace 'root\default' -ClassName StdRegProv -OperationTimeoutSec 15 -ErrorAction Stop
            $val = Invoke-CimMethod -InputObject $regProv -MethodName GetStringValue -Arguments @{
                hDefKey     = 2147483650
                sSubKeyName = "SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate"
                sValueName  = "WUServer"
            } -OperationTimeoutSec 15 -ErrorAction Stop
            $result.WSUS = $val.sValue
        } catch { Note-Error $_ }
    }

    Remove-CimSession $session -ErrorAction SilentlyContinue
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


def _build_command(computer_name: str) -> list[str]:
    # Embed the name as a single-quoted PowerShell literal (doubling any
    # embedded quote) instead of relying on param binding, which doesn't work
    # through `powershell -Command`.
    escaped = computer_name.replace("'", "''")
    script = f"$ComputerName = '{escaped}'\n" + _CHECK_SCRIPT
    return ["powershell", "-NoProfile", "-NonInteractive", "-Command", script]


def check_computer(computer_name: str, timeout: float = 60.0) -> dict:
    """Runs every check for a single computer in one PowerShell round-trip.

    Never raises: timeouts and PowerShell failures come back as a result
    dict with the "error" field set, so a bad machine can't abort a scan.
    """
    try:
        result = run_hidden(_build_command(computer_name), timeout=timeout)
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
