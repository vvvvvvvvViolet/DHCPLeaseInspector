"""Runs the combined per-computer health check (ping, domain, DHCP, WSUS, OS)."""
import json

from .process_utils import run_hidden

_CHECK_SCRIPT = r"""
param($ComputerName)
$result = [ordered]@{
    ComputerName = $ComputerName
    Ping = $false
    PartOfDomain = $null
    Domain = $null
    DHCPServer = $null
    OSVersion = $null
    LastBoot = $null
    WSUS = $null
}

try {
    $result.Ping = [bool](Test-Connection -ComputerName $ComputerName -Count 1 -Quiet -ErrorAction Stop)
} catch {
    $result.Ping = $false
}

if ($result.Ping) {
    try {
        $cs = Get-CimInstance -ComputerName $ComputerName -ClassName Win32_ComputerSystem -ErrorAction Stop
        $result.PartOfDomain = [bool]$cs.PartOfDomain
        $result.Domain = $cs.Domain
    } catch {}

    try {
        $os = Get-CimInstance -ComputerName $ComputerName -ClassName Win32_OperatingSystem -ErrorAction Stop
        $result.OSVersion = $os.Caption
        $result.LastBoot = $os.LastBootUpTime.ToString("o")
    } catch {}

    try {
        $nic = Get-CimInstance -ComputerName $ComputerName -ClassName Win32_NetworkAdapterConfiguration `
            -Filter "IPEnabled=True AND DHCPEnabled=True" -ErrorAction Stop | Select-Object -First 1
        $result.DHCPServer = $nic.DHCPServer
    } catch {}

    try {
        $regProv = Get-CimInstance -ComputerName $ComputerName -Namespace 'root\default' -ClassName StdRegProv -ErrorAction Stop
        $val = Invoke-CimMethod -InputObject $regProv -MethodName GetStringValue -Arguments @{
            hDefKey     = 2147483650
            sSubKeyName = "SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate"
            sValueName  = "WUServer"
        } -ErrorAction Stop
        $result.WSUS = $val.sValue
    } catch {}
}

$result | ConvertTo-Json -Compress
"""


def check_computer(computer_name: str, timeout: float = 20.0) -> dict:
    """Runs every check for a single computer in one PowerShell round-trip."""
    result = run_hidden(
        [
            "powershell", "-NoProfile", "-NonInteractive", "-Command", _CHECK_SCRIPT,
            "-ComputerName", computer_name,
        ],
        timeout=timeout,
    )

    if result.returncode != 0 or not result.stdout.strip():
        return {
            "computer_name": computer_name,
            "ping": False,
            "part_of_domain": None,
            "domain": None,
            "dhcp_server": None,
            "os_version": None,
            "last_boot": None,
            "wsus": None,
            "error": result.stderr.strip() or "No response",
        }

    data = json.loads(result.stdout.strip())
    return {
        "computer_name": data.get("ComputerName", computer_name),
        "ping": bool(data.get("Ping")),
        "part_of_domain": data.get("PartOfDomain"),
        "domain": data.get("Domain"),
        "dhcp_server": data.get("DHCPServer"),
        "os_version": data.get("OSVersion"),
        "last_boot": data.get("LastBoot"),
        "wsus": data.get("WSUS"),
        "error": None,
    }
