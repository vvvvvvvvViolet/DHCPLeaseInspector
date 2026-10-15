"""Step-by-step diagnosis of one machine: why do its columns come back empty?

A normal scan collapses everything into "Error" or "-". This runs each
check on its own, timing it and keeping the real error text, so the failing
layer is visible: name resolution, the network path, the RPC port DCOM
needs, authentication, or one particular WMI class.

Each step is {"name", "ok", "ms", "detail", "hint", "optional"}. ok is True
(passed), False (failed) or None (skipped because an earlier step made it
pointless). optional steps are informational: failing one does not mean the
machine is unhealthy (many networks have no reverse-DNS records, say).
"""
import json
import platform
import socket
import subprocess
import time
from datetime import datetime

from . import checks, config
from .process_utils import run_powershell

REMOTE_STEPS = [
    "Open DCOM session",
    "WMI: Win32_ComputerSystem",
    "WMI: Win32_OperatingSystem",
    "WMI: Win32_NetworkAdapterConfiguration",
    "WMI: Win32_QuickFixEngineering",
    "Registry read (StdRegProv)",
]

# Matched against the failure text, lower-cased. Hex codes are listed beside
# the English wording because Windows localises the message but not the code.
_HINTS = [
    (("access is denied", "0x80070005", "0x80041003", "e_accessdenied"),
     "Access denied: the account used is not an administrator on that machine (or DCOM/WMI "
     "permissions are restricted). Set an administrator account under Credentials."),
    (("user name or password is incorrect", "logon failure", "0x8007052e", "0x8007052f"),
     "The account was rejected: the username or password in Credentials is wrong, expired or locked out."),
    (("rpc server is unavailable", "0x800706ba"),
     "RPC server unavailable: the machine is off or unreachable, or a firewall is blocking DCOM "
     "(TCP 135 plus the dynamic RPC ports). Enable the 'Windows Management Instrumentation (DCOM-In)' "
     "firewall rule on the target."),
    (("network path was not found", "0x80070035"),
     "The network path was not found: the name does not resolve to this machine, or it is unreachable."),
    (("invalid namespace", "0x8004100e"),
     "The WMI namespace is missing: the machine's WMI repository may be damaged "
     "(winmgmt /verifyrepository on the target)."),
    (("timed out", "timeout", "0x80041032"),
     "The machine did not answer in time: it is slow, busy, or a firewall is silently dropping the traffic."),
]


def hint_for(error: str) -> str:
    text = (error or "").casefold()
    for needles, hint in _HINTS:
        if any(needle in text for needle in needles):
            return hint
    return ""


def _step(name, ok, ms, detail="", hint="", optional=False):
    return {"name": name, "ok": ok, "ms": ms, "detail": detail, "hint": hint, "optional": optional}


def _skipped(name, reason, optional=False):
    return _step(name, None, None, reason, optional=optional)


def _first_line(text: str) -> str:
    lines = [line.strip() for line in (text or "").splitlines() if line.strip()]
    return lines[0] if lines else ""


def _timed(fn):
    """Run fn() -> (ok, detail); return (ok, detail, elapsed_ms). Never raises."""
    start = time.perf_counter()
    try:
        ok, detail = fn()
    except Exception as exc:  # a diagnostic must report, not crash
        ok, detail = False, f"{type(exc).__name__}: {exc}"
    return ok, detail, int((time.perf_counter() - start) * 1000)


def _tcp(ip: str, port: int, timeout: float = 3.0):
    try:
        with socket.create_connection((ip, port), timeout=timeout):
            return True, "connected"
    except socket.timeout:
        return False, f"no answer within {timeout:.0f}s (filtered, or the host is off)"
    except OSError as exc:
        return False, str(exc) or type(exc).__name__


def _remote_script(computer: str) -> str:
    escaped = computer.replace("'", "''")
    return f"$ComputerName = '{escaped}'\n" + _REMOTE_SCRIPT


_REMOTE_SCRIPT = r"""
$result = [ordered]@{ FirstError = $null }
$steps = New-Object System.Collections.ArrayList

function Add-Step($name, $ok, $ms, $detail, $err) {
    [void]$steps.Add([ordered]@{ Name = $name; Ok = $ok; Ms = [int]$ms; Detail = $detail; Error = $err })
}

# Runs one probe on its own, so one failing class cannot hide the others.
function Run-Step($name, [scriptblock]$body) {
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    try {
        $detail = & $body
        Add-Step $name $true $sw.ElapsedMilliseconds ([string]$detail) $null
    } catch {
        Add-Step $name $false $sw.ElapsedMilliseconds $null (($_ | Out-String).Trim())
    }
}

$sw = [System.Diagnostics.Stopwatch]::StartNew()
""" + checks._SESSION_PREAMBLE + r"""
if ($session) {
    Add-Step 'Open DCOM session' $true $sw.ElapsedMilliseconds 'connected' $null

    Run-Step 'WMI: Win32_ComputerSystem' {
        $c = Get-CimInstance -CimSession $session -ClassName Win32_ComputerSystem -OperationTimeoutSec 15 -ErrorAction Stop
        "name=$($c.Name) domain=$($c.Domain) user=$($c.UserName)"
    }
    Run-Step 'WMI: Win32_OperatingSystem' {
        $o = Get-CimInstance -CimSession $session -ClassName Win32_OperatingSystem -OperationTimeoutSec 15 -ErrorAction Stop
        "$($o.Caption) (last boot $($o.LastBootUpTime.ToString('yyyy-MM-dd HH:mm')))"
    }
    Run-Step 'WMI: Win32_NetworkAdapterConfiguration' {
        $n = @(Get-CimInstance -CimSession $session -ClassName Win32_NetworkAdapterConfiguration `
            -Filter "IPEnabled=True" -OperationTimeoutSec 15 -ErrorAction Stop)
        $first = $n | Select-Object -First 1
        "$($n.Count) adapter(s); mac=$($first.MACAddress) dhcp=$($first.DHCPServer)"
    }
    Run-Step 'WMI: Win32_QuickFixEngineering' {
        $q = @(Get-CimInstance -CimSession $session -ClassName Win32_QuickFixEngineering -OperationTimeoutSec 15 -ErrorAction Stop)
        "$($q.Count) hotfix(es)"
    }
    Run-Step 'Registry read (StdRegProv)' {
        $r = Invoke-CimMethod -CimSession $session -Namespace 'root\default' -ClassName StdRegProv `
            -MethodName EnumKey -Arguments @{ hDefKey = [uint32]2147483650; sSubKeyName = 'SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall' } `
            -OperationTimeoutSec 15 -ErrorAction Stop
        if ($r.ReturnValue -ne 0) { throw "StdRegProv returned code $($r.ReturnValue)" }
        "$(@($r.sNames).Count) uninstall key(s) readable"
    }
    Remove-CimSession $session -ErrorAction SilentlyContinue
} else {
    Add-Step 'Open DCOM session' $false $sw.ElapsedMilliseconds $null $result.FirstError
}

ConvertTo-Json -InputObject @($steps) -Compress -Depth 4
"""


def _remote_steps(computer, credential, timeout):
    """Run the WMI probes in one PowerShell process; returns the step list."""
    try:
        proc = run_powershell(_remote_script(computer), timeout=timeout,
                              env=checks._credential_env(credential))
    except subprocess.TimeoutExpired:
        failure = f"PowerShell did not finish within {timeout:.0f}s"
        return [_step(REMOTE_STEPS[0], False, None, failure, hint_for("timed out"))] + \
               [_skipped(name, "not reached") for name in REMOTE_STEPS[1:]]
    except OSError as exc:
        return [_step(REMOTE_STEPS[0], False, None, f"Could not start PowerShell: {exc}")] + \
               [_skipped(name, "not reached") for name in REMOTE_STEPS[1:]]

    try:
        data = json.loads((proc.stdout or "").strip())
    except ValueError:
        detail = _first_line(proc.stderr) or "PowerShell returned no usable output"
        return [_step(REMOTE_STEPS[0], False, None, detail)] + \
               [_skipped(name, "not reached") for name in REMOTE_STEPS[1:]]
    if isinstance(data, dict):
        data = [data]

    by_name, steps = {}, []
    for entry in data:
        ok = bool(entry.get("Ok"))
        error = (entry.get("Error") or "").strip()
        detail = entry.get("Detail") or (_first_line(error) if error else "")
        by_name[entry.get("Name")] = _step(
            entry.get("Name"), ok, entry.get("Ms"), detail,
            "" if ok else hint_for(error))
        if not ok and error:
            by_name[entry.get("Name")]["error"] = error
    session_ok = by_name.get(REMOTE_STEPS[0], {}).get("ok")
    for name in REMOTE_STEPS:
        if name in by_name:
            steps.append(by_name[name])
        elif session_ok is False:
            steps.append(_skipped(name, "skipped — no DCOM session"))
        else:
            steps.append(_skipped(name, "not reached"))
    return steps


def diagnose(target: str, credential=None, on_step=None, ping_timeout_ms=None, remote_timeout=150.0):
    """Run every check against one target (a name or an IP). Returns the steps.

    on_step, if given, is called with each step as soon as it is known.
    """
    target = (target or "").strip()
    if ping_timeout_ms is None:
        ping_timeout_ms = config.get_settings().ping_timeout_ms
    steps = []

    def emit(step):
        steps.append(step)
        if on_step:
            on_step(step)
        return step

    # --- name resolution ---
    ip = None
    if checks._is_ip_literal(target):
        ip = target
        emit(_skipped("DNS lookup", "not needed — the target is an IP address"))
    else:
        ok, detail, ms = _timed(lambda: (True, socket.gethostbyname(target)))
        if ok:
            ip = detail
            emit(_step("DNS lookup", True, ms, f"resolves to {ip}"))
        else:
            emit(_step("DNS lookup", False, ms, detail,
                       "The name does not resolve: check the spelling and DNS suffix, or the machine was "
                       "removed. Try its IP address instead."))
    if ip is None:
        for name in ["Ping", "TCP 135 (RPC endpoint mapper)"] + REMOTE_STEPS:
            emit(_skipped(name, "skipped — no address to test"))
        return steps

    # --- network path ---
    ok, _, ms = _timed(lambda: (checks._ping(ip, ping_timeout_ms), ""))
    emit(_step("Ping", ok, ms, "reply received" if ok else
               "no reply — the host may be off, or ICMP is blocked (not conclusive on its own)"))

    ok135, detail, ms = _timed(lambda: _tcp(ip, 135))
    emit(_step("TCP 135 (RPC endpoint mapper)", ok135, ms, detail, "" if ok135 else
               "Port 135 is closed or filtered, so DCOM/WMI cannot work: the host is off, or its firewall "
               "blocks it (rule 'Windows Management Instrumentation (DCOM-In)')."))

    # --- informational lookups ---
    ok, detail, ms = _timed(lambda: (True, socket.gethostbyaddr(ip)[0]))
    emit(_step("Reverse DNS (PTR)", ok, ms, detail if ok else
               "no PTR record — normal on many networks", optional=True))
    name = checks.netbios_name(ip)
    emit(_step("NetBIOS name", bool(name), None,
               name or "no answer (NetBIOS is often disabled, or unavailable on this OS)", optional=True))
    mac = checks.arp_mac(ip)
    emit(_step("MAC from ARP cache", bool(mac), None,
               mac or "not in the ARP cache (different subnet, or unavailable on this OS)", optional=True))
    ok445, detail, ms = _timed(lambda: _tcp(ip, 445))
    emit(_step("TCP 445 (SMB)", ok445, ms, detail, optional=True))

    # --- WMI over DCOM ---
    if not ok135:
        # DCOM always starts at port 135; trying anyway would only wait out
        # the timeouts.
        for name in REMOTE_STEPS:
            emit(_skipped(name, "skipped — RPC port 135 is unreachable"))
        return steps
    for step in _remote_steps(target, credential, remote_timeout):
        emit(step)
    return steps


# --- report ---------------------------------------------------------------

def summarise(steps) -> dict:
    required = [s for s in steps if not s["optional"]]
    return {
        "passed": sum(1 for s in required if s["ok"] is True),
        "failed": sum(1 for s in required if s["ok"] is False),
        "skipped": sum(1 for s in required if s["ok"] is None),
        "info": sum(1 for s in steps if s["optional"]),
    }


def format_report(target: str, steps, credential=None) -> str:
    """Plain text for pasting into a message. Never contains the password."""
    counts = summarise(steps)
    lines = [
        "DHCP Lease Inspector - diagnostic report",
        f"Target: {target}",
        f"Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        f"Connecting as: {'alternate account ' + credential[0] if credential and credential[0] else 'the current Windows user'}",
        f"Run from: {platform.platform()}",
        f"Result: {counts['passed']} passed, {counts['failed']} failed, "
        f"{counts['skipped']} skipped, {counts['info']} informational",
        "",
    ]
    for step in steps:
        if step["ok"] is True:
            tag = "OK  "
        elif step["ok"] is None:
            tag = "SKIP"
        else:
            tag = "INFO" if step["optional"] else "FAIL"
        timing = f"{step['ms']} ms" if step["ms"] is not None else ""
        lines.append(f"[{tag}] {step['name']}  {timing}".rstrip())
        if step["detail"]:
            lines.append(f"       {step['detail']}")
        if step.get("error") and step["error"] != step["detail"]:
            lines.append(f"       raw error: {step['error']}")
    hints = []
    for step in steps:
        if step["ok"] is False and not step["optional"] and step["hint"] and step["hint"] not in hints:
            hints.append(step["hint"])
    if hints:
        lines += ["", "What to try:"] + [f"  - {hint}" for hint in hints]
    elif counts["failed"] == 0 and counts["skipped"] == 0:
        lines += ["", "Everything this machine needs to be scanned answered correctly."]
    return "\n".join(lines)
