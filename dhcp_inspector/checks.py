"""Per-computer probes: fast DNS/ping sweep, then a WMI check over DCOM."""
import json
import os
import socket
import subprocess
import sys

from . import config
from .process_utils import run_hidden

# Alternate credentials are handed to PowerShell through these env vars, not
# the command line (which would show up in the process list) and never a
# file. The child process gets its own copy; nothing is persisted.
_CRED_USER_ENV = "DHCPINSPECT_USER"
_CRED_PASS_ENV = "DHCPINSPECT_PASS"


def resolve_and_ping(computer_name: str, ping_timeout_ms: int | None = None) -> dict:
    """Phase-1 probe: resolve the name in DNS, then send one ping.

    Distinguishes "no DNS record" (machine likely decommissioned) from
    "resolves but doesn't answer" (off / firewalled). Never raises.
    """
    if ping_timeout_ms is None:
        ping_timeout_ms = config.get_settings().ping_timeout_ms

    try:
        ip = socket.gethostbyname(computer_name)
    except OSError:
        return {"ip": None, "dns_ok": False, "ping": False, "error": "DNS lookup failed"}

    if sys.platform == "win32":
        args = ["ping", "-n", "1", "-w", str(ping_timeout_ms), ip]
    else:
        args = ["ping", "-c", "1", "-W", str(max(ping_timeout_ms // 1000, 1)), ip]

    try:
        result = run_hidden(args, timeout=ping_timeout_ms / 1000 + 5)
    except (subprocess.TimeoutExpired, OSError):
        return {"ip": ip, "dns_ok": True, "ping": False, "error": None}

    # On Windows, "Destination host unreachable" still exits 0 — a real reply
    # always carries a TTL.
    ok = result.returncode == 0
    if ok and sys.platform == "win32":
        ok = "TTL=" in (result.stdout or "").upper()
    return {"ip": ip, "dns_ok": True, "ping": ok, "error": None}


# The computer name is prepended as a $ComputerName assignment (see
# _build_command). We deliberately do NOT use `param(...)` + a trailing
# `-ComputerName` argument: with `powershell -Command "<script>"`, anything
# after the script string is treated as command text, not bound to param(),
# so $ComputerName would come back null and every machine would fail.
# Ping is handled in Python (resolve_and_ping); this script is WMI-only.
_CHECK_SCRIPT = r"""
$result = [ordered]@{
    ComputerName = $ComputerName
    WmiOk = $false
    PartOfDomain = $null
    Domain = $null
    DHCPServer = $null
    OSVersion = $null
    LastBoot = $null
    FirstError = $null
}

function Note-Error($err) {
    if ($null -eq $result.FirstError) {
        $result.FirstError = ($err | Out-String).Trim()
    }
}

# Query over DCOM, not the CIM default (WS-Man/WinRM): WinRM is rarely
# enabled on ordinary domain workstations, whereas DCOM/WMI works out of
# the box wherever the firewall allows it. -OperationTimeoutSec bounds each
# call so a dead or unreachable host fails fast instead of hanging on RPC.
$session = $null
try {
    $opt = New-CimSessionOption -Protocol Dcom
    $cimArgs = @{
        ComputerName        = $ComputerName
        SessionOption       = $opt
        OperationTimeoutSec = 15
        ErrorAction         = 'Stop'
    }
    # Use alternate credentials only when the launcher supplied them.
    if ($env:DHCPINSPECT_USER) {
        $secpw = ConvertTo-SecureString $env:DHCPINSPECT_PASS -AsPlainText -Force
        $cimArgs.Credential = New-Object System.Management.Automation.PSCredential($env:DHCPINSPECT_USER, $secpw)
    }
    $session = New-CimSession @cimArgs
} catch { Note-Error $_ }

if ($session) {
    try {
        $cs = Get-CimInstance -CimSession $session -ClassName Win32_ComputerSystem -OperationTimeoutSec 15 -ErrorAction Stop
        $result.WmiOk = $true
        $result.PartOfDomain = [bool]$cs.PartOfDomain
        $result.Domain = $cs.Domain
    } catch { Note-Error $_ }

    # Only keep probing once the first WMI call proves the host answers, so a
    # dead machine costs one timed-out call, not three.
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
    }

    Remove-CimSession $session -ErrorAction SilentlyContinue
}

$result | ConvertTo-Json -Compress
"""


def _failed_result(computer_name: str, error: str) -> dict:
    return {
        "computer_name": computer_name,
        "wmi_ok": False,
        "part_of_domain": None,
        "domain": None,
        "dhcp_server": None,
        "os_version": None,
        "last_boot": None,
        "error": error,
    }


def _build_command(computer_name: str) -> list[str]:
    # Embed the name as a single-quoted PowerShell literal (doubling any
    # embedded quote) instead of relying on param binding, which doesn't work
    # through `powershell -Command`.
    escaped = computer_name.replace("'", "''")
    script = f"$ComputerName = '{escaped}'\n" + _CHECK_SCRIPT
    return ["powershell", "-NoProfile", "-NonInteractive", "-Command", script]


def _credential_env(credential: tuple[str, str] | None) -> dict | None:
    """Build the child-process environment carrying alternate credentials.

    Returns None (inherit the parent env) when no credential is given.
    """
    if not credential or not credential[0]:
        return None
    env = dict(os.environ)
    env[_CRED_USER_ENV] = credential[0]
    env[_CRED_PASS_ENV] = credential[1] or ""
    return env


def check_computer(
    computer_name: str,
    timeout: float | None = None,
    credential: tuple[str, str] | None = None,
) -> dict:
    """Runs the WMI checks for a single computer in one PowerShell round-trip.

    credential, when given, is a (username, password) pair used for the
    remote WMI/DCOM connection instead of the caller's own identity.

    Never raises: timeouts and PowerShell failures come back as a result
    dict with the "error" field set, so a bad machine can't abort a scan.
    """
    if timeout is None:
        timeout = float(config.get_settings().wmi_timeout_s)
    try:
        result = run_hidden(
            _build_command(computer_name),
            timeout=timeout,
            env=_credential_env(credential),
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
        "wmi_ok": wmi_ok,
        "part_of_domain": data.get("PartOfDomain"),
        "domain": data.get("Domain"),
        "dhcp_server": data.get("DHCPServer"),
        "os_version": data.get("OSVersion"),
        "last_boot": data.get("LastBoot"),
        # Surface the WMI error only when nothing succeeded — a machine that
        # answered WMI but denied one sub-query is still a usable result.
        "error": None if wmi_ok else data.get("FirstError"),
    }
