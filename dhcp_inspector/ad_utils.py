"""Loads the computer list from Active Directory."""
import json

from .process_utils import run_hidden

def _build_script(name_filter: str) -> str:
    if name_filter:
        # PowerShell single-quoted string: escaping is just doubling quotes,
        # which keeps a user-typed filter from breaking out of the -Filter
        # expression.
        escaped = name_filter.replace("'", "''")
        ad_filter = f"Name -like '*{escaped}*'"
    else:
        ad_filter = "*"
    return (
        f'Get-ADComputer -Filter "{ad_filter}" -Properties Name | '
        "Select-Object -ExpandProperty Name | ConvertTo-Json -Compress"
    )


def load_ad_computers(name_filter: str = "") -> list[str]:
    """Return computer names found in Active Directory.

    name_filter, when given, becomes a substring match on the computer name
    (Name -like '*<filter>*'), so a big domain can be narrowed before the
    full query runs. Requires the RSAT ActiveDirectory PowerShell module and
    enough rights to query the domain.
    """
    result = run_hidden(
        ["powershell", "-NoProfile", "-NonInteractive", "-Command",
         _build_script(name_filter.strip())],
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
