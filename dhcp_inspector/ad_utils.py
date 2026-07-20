"""Loads the computer list from Active Directory."""
import json

from .process_utils import run_hidden

_LOAD_AD_SCRIPT = (
    "Get-ADComputer -Filter * -Properties Name | "
    "Select-Object -ExpandProperty Name | ConvertTo-Json -Compress"
)


def load_ad_computers() -> list[str]:
    """Return every computer name found in Active Directory.

    Requires the RSAT ActiveDirectory PowerShell module and enough rights
    to query the domain.
    """
    result = run_hidden(
        ["powershell", "-NoProfile", "-NonInteractive", "-Command", _LOAD_AD_SCRIPT],
        timeout=60,
    )
    if result.returncode != 0:
        raise RuntimeError(
            result.stderr.strip()
            or "Get-ADComputer failed. Make sure the ActiveDirectory PowerShell "
            "module (RSAT) is installed and you're running on a domain-joined "
            "machine with rights to query AD."
        )

    output = result.stdout.strip()
    if not output:
        return []

    data = json.loads(output)
    if isinstance(data, str):
        return [data]
    return list(data)
