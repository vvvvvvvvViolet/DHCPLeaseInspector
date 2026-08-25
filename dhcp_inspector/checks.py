"""Per-computer probes: fast DNS/ping sweep, then a WMI check over DCOM."""
import ipaddress
import json
import os
import re
import socket
import subprocess
import sys

from . import config
from .process_utils import run_hidden, run_powershell

# Alternate credentials are handed to PowerShell through these env vars, not
# the command line (which would show up in the process list) and never a
# file. The child process gets its own copy; nothing is persisted.
_CRED_USER_ENV = "DHCPINSPECT_USER"
_CRED_PASS_ENV = "DHCPINSPECT_PASS"


def _is_ip_literal(target: str) -> bool:
    try:
        ipaddress.ip_address(target)
    except ValueError:
        return False
    return True


def _ping(ip: str, ping_timeout_ms: int) -> bool:
    if sys.platform == "win32":
        args = ["ping", "-n", "1", "-w", str(ping_timeout_ms), ip]
    else:
        args = ["ping", "-c", "1", "-W", str(max(ping_timeout_ms // 1000, 1)), ip]

    try:
        result = run_hidden(args, timeout=ping_timeout_ms / 1000 + 5)
    except (subprocess.TimeoutExpired, OSError):
        return False

    # On Windows, "Destination host unreachable" still exits 0 — a real reply
    # always carries a TTL.
    ok = result.returncode == 0
    if ok and sys.platform == "win32":
        ok = "TTL=" in (result.stdout or "").upper()
    return ok


# nbtstat's name table lists the machine name against the <00> UNIQUE entry.
# The Status column is localised on non-English Windows, so only the
# language-independent part of the line is matched.
_NBT_NAME = re.compile(r"^\s*(\S+)\s*<00>\s+UNIQUE", re.MULTILINE | re.IGNORECASE)


# `arp -a <ip>` prints "  10.20.30.5   00-11-22-33-44-55   dynamic"; the Type
# column is localised on non-English Windows, so only the pair is matched.
_ARP_MAC = re.compile(
    r"^\s*(?:\d{1,3}\.){3}\d{1,3}\s+([0-9a-f]{2}(?:[-:][0-9a-f]{2}){5})",
    re.MULTILINE | re.IGNORECASE,
)


def arp_mac(ip: str, timeout: float = 5.0) -> str | None:
    """Read the host's MAC from the local ARP cache.

    The ping just sent populates the cache, so this costs one local lookup
    and no access to the target at all. Only works for hosts on the same
    layer-2 segment; returns None for anything routed.
    """
    if sys.platform != "win32":
        return None
    try:
        result = run_hidden(["arp", "-a", ip], timeout=timeout)
    except (subprocess.TimeoutExpired, OSError):
        return None
    match = _ARP_MAC.search(result.stdout or "")
    return match.group(1) if match else None


def netbios_name(ip: str, timeout: float = 5.0) -> str | None:
    """Ask the host for its NetBIOS name. Works without any DNS record.

    The fallback for machines that answer ping but have no PTR entry and
    can't be reached over WMI. Returns None on any failure.
    """
    if sys.platform != "win32":
        return None
    try:
        result = run_hidden(["nbtstat", "-A", ip], timeout=timeout)
    except (subprocess.TimeoutExpired, OSError):
        return None
    match = _NBT_NAME.search(result.stdout or "")
    return match.group(1) if match else None


def resolve_and_ping(target: str, ping_timeout_ms: int | None = None) -> dict:
    """Phase-1 probe: work out the address, then send one ping.

    `target` is either a computer name (forward-resolved via DNS) or a bare
    IP address from a subnet scan, in which case the name is looked up in
    reverse instead and returned as "resolved_name". For names this
    distinguishes "no DNS record" (machine likely decommissioned) from
    "resolves but doesn't answer" (off / firewalled). Never raises.
    """
    if ping_timeout_ms is None:
        ping_timeout_ms = config.get_settings().ping_timeout_ms

    if _is_ip_literal(target):
        ip = target
        ok = _ping(ip, ping_timeout_ms)
        # Only pay for name lookups on addresses that actually answered —
        # a dead /24 would otherwise cost hundreds of pointless queries.
        resolved_name = None
        arp = None
        if ok:
            try:
                resolved_name = socket.gethostbyaddr(ip)[0]
            except OSError:
                # No PTR record (common on networks that don't register
                # reverse DNS) — ask the host over NetBIOS instead.
                resolved_name = netbios_name(ip)
            arp = arp_mac(ip)
        return {
            "ip": ip,
            "dns_ok": True,   # nothing to resolve; the address was given
            "ping": ok,
            "resolved_name": resolved_name,
            "arp_mac": arp,
            "error": None,
        }

    try:
        ip = socket.gethostbyname(target)
    except OSError:
        return {"ip": None, "dns_ok": False, "ping": False, "error": "DNS lookup failed"}

    ok = _ping(ip, ping_timeout_ms)
    return {
        "ip": ip,
        "dns_ok": True,
        "ping": ok,
        "arp_mac": arp_mac(ip) if ok else None,
        "error": None,
    }


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
    Name = $null
    UserName = $null
    Mac = $null
    PartOfDomain = $null
    Domain = $null
    DHCPServer = $null
    OSVersion = $null
    LastBoot = $null
    LastPatch = $null
    RecentHotfixes = $null
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
        # The machine's own name — the authoritative answer for a subnet scan,
        # where the target is an IP and DNS may hold no PTR record.
        $result.Name = if ($cs.DNSHostName) { $cs.DNSHostName } else { $cs.Name }
        # Whoever holds the interactive console session, as DOMAIN\user. Null
        # when nobody is signed in locally (an RDP-only session doesn't set it).
        $result.UserName = $cs.UserName
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
            $result.Mac = $nic.MACAddress
        } catch { Note-Error $_ }

        try {
            # Win32_QuickFixEngineering.InstalledOn is a loosely-typed string;
            # -as [DateTime] returns $null (no throw) for the odd blank/garbage
            # value, so filter to the parseable ones, then take the newest.
            $qfe = Get-CimInstance -CimSession $session -ClassName Win32_QuickFixEngineering `
                -OperationTimeoutSec 15 -ErrorAction Stop |
                Where-Object { $_.InstalledOn -and ($_.InstalledOn -as [DateTime]) } |
                Sort-Object { $_.InstalledOn -as [DateTime] } -Descending
            if ($qfe) {
                $latest = @($qfe)[0]
                $result.LastPatch = ([DateTime]$latest.InstalledOn).ToString("o")
                $result.RecentHotfixes = (@($qfe) | Select-Object -First 5 | ForEach-Object {
                    "{0} ({1})" -f $_.HotFixID, (([DateTime]$_.InstalledOn).ToString("yyyy-MM-dd"))
                }) -join "; "
            }
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
        "wmi_name": None,
        "user_login": None,
        "wmi_mac": None,
        "part_of_domain": None,
        "domain": None,
        "dhcp_server": None,
        "os_version": None,
        "last_boot": None,
        "last_patch": None,
        "recent_hotfixes": None,
        "error": error,
    }


def _build_script(computer_name: str) -> str:
    # Embed the name as a single-quoted PowerShell literal (doubling any
    # embedded quote) instead of relying on param binding, which doesn't work
    # through `powershell -Command`.
    escaped = computer_name.replace("'", "''")
    return f"$ComputerName = '{escaped}'\n" + _CHECK_SCRIPT


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
        result = run_powershell(
            _build_script(computer_name),
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
        "wmi_name": data.get("Name"),
        "user_login": data.get("UserName"),
        "wmi_mac": data.get("Mac"),
        "part_of_domain": data.get("PartOfDomain"),
        "domain": data.get("Domain"),
        "dhcp_server": data.get("DHCPServer"),
        "os_version": data.get("OSVersion"),
        "last_boot": data.get("LastBoot"),
        "last_patch": data.get("LastPatch"),
        "recent_hotfixes": data.get("RecentHotfixes"),
        # Surface the WMI error only when nothing succeeded — a machine that
        # answered WMI but denied one sub-query is still a usable result.
        "error": None if wmi_ok else data.get("FirstError"),
    }
