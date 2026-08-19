"""Reads the Windows DHCP server's lease table to map addresses to names.

This is the most reliable way to name a host that can't be reached: the
DHCP server already recorded who asked for the address, so nothing has to
be queried from the machine itself.
"""
import json

from .process_utils import run_powershell

_LEASE_SCRIPT = """
$ErrorActionPreference = 'Stop'
$scopes = Get-DhcpServerv4Scope @ServerArg
$scopes | ForEach-Object {
    Get-DhcpServerv4Lease @ServerArg -ScopeId $_.ScopeId
} | Select-Object `
    @{Name='IP';Expression={ $_.IPAddress.IPAddressToString }}, `
    @{Name='Name';Expression={ $_.HostName }}, `
    @{Name='Mac';Expression={ $_.ClientId }} |
    ConvertTo-Json -Compress
"""


def _build_script(server: str) -> str:
    if server:
        escaped = server.replace("'", "''")
        server_arg = f"$ServerArg = @{{ ComputerName = '{escaped}' }}\n"
    else:
        # No server named: query the DHCP service on this machine.
        server_arg = "$ServerArg = @{}\n"
    return server_arg + _LEASE_SCRIPT


def load_leases(server: str = "", timeout: float = 120.0) -> dict[str, dict]:
    """Return {ip: {"name": ..., "mac": ...}} for every lease on the server.

    Raises RuntimeError when the DHCP cmdlets are unavailable or the server
    can't be queried.
    """
    result = run_powershell(_build_script(server.strip()), timeout=timeout)
    if result.returncode != 0:
        raise RuntimeError(
            result.stderr.strip()
            or "Could not read DHCP leases. Install the DHCP Server Tools "
            "(RSAT) and make sure you can query the DHCP server."
        )

    output = (result.stdout or "").strip()
    if not output:
        return {}

    try:
        data = json.loads(output)
    except ValueError:
        raise RuntimeError("Unexpected output from the DHCP lease query")

    if isinstance(data, dict):  # a single lease isn't wrapped in a list
        data = [data]

    leases = {}
    for entry in data:
        ip = entry.get("IP")
        if not ip:
            continue
        name = (entry.get("Name") or "").strip()
        leases[ip] = {
            # Lease host names are often stored fully qualified.
            "name": name or None,
            "mac": entry.get("Mac"),
        }
    return leases
