"""Loads the computer list (and per-computer AD facts) from Active Directory."""
import json

from .process_utils import run_powershell


def _build_script(name_filter: str) -> str:
    if name_filter:
        # PowerShell single-quoted string: escaping is just doubling quotes,
        # which keeps a user-typed filter from breaking out of the -Filter
        # expression.
        escaped = name_filter.replace("'", "''")
        ad_filter = f"Name -like '*{escaped}*'"
    else:
        ad_filter = "*"
    # Pull the facts the domain check needs straight from AD, so the Domain
    # column is populated even for machines we can't reach over WMI.
    # LastLogonTimestamp is the replicated attribute — it can lag up to ~14
    # days behind the true last logon, but needs no per-DC querying.
    return (
        f'Get-ADComputer -Filter "{ad_filter}" '
        "-Properties DNSHostName,OperatingSystem,Enabled,PasswordLastSet,LastLogonTimestamp | "
        "Select-Object Name,DistinguishedName,OperatingSystem,Enabled,"
        "@{Name='PasswordLastSet';Expression={ if ($_.PasswordLastSet) "
        "{ $_.PasswordLastSet.ToString('o') } else { $null } }},"
        "@{Name='LastLogon';Expression={ if ($_.LastLogonTimestamp) "
        "{ [DateTime]::FromFileTime($_.LastLogonTimestamp).ToString('o') } else { $null } }} | "
        "ConvertTo-Json -Compress"
    )


def _domain_from_dn(distinguished_name: str | None) -> str | None:
    """Turn a computer DN into its DNS domain, e.g.
    'CN=PC1,OU=Lab,DC=corp,DC=example,DC=com' -> 'corp.example.com'.
    """
    if not distinguished_name:
        return None
    parts = [
        piece[3:]
        for piece in distinguished_name.split(",")
        if piece.strip().upper().startswith("DC=")
    ]
    return ".".join(parts) if parts else None


def load_ad_computers(name_filter: str = "") -> list[dict]:
    """Return per-computer AD records found in Active Directory.

    Each record: {name, domain, ad_os, enabled, password_last_set}. The
    name_filter, when given, is a substring match on the computer name
    (Name -like '*<filter>*') so a big domain can be narrowed before the
    full query runs. Requires the RSAT ActiveDirectory PowerShell module and
    rights to query the domain.
    """
    result = run_powershell(_build_script(name_filter.strip()), timeout=120)
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
    if isinstance(data, dict):  # a single computer isn't wrapped in a list
        data = [data]

    records = []
    for entry in data:
        records.append({
            "name": entry.get("Name"),
            "domain": _domain_from_dn(entry.get("DistinguishedName")),
            "ad_os": entry.get("OperatingSystem"),
            "enabled": entry.get("Enabled"),
            "password_last_set": entry.get("PasswordLastSet"),
            "last_logon": entry.get("LastLogon"),
        })
    return records
