"""Domain join status and OS version checks (Windows)."""
import json
import subprocess


def _run_powershell(command: str) -> str:
    result = subprocess.run(
        ["powershell", "-NoProfile", "-NonInteractive", "-Command", command],
        capture_output=True,
        text=True,
        timeout=20,
    )
    if result.returncode != 0:
        raise RuntimeError(result.stderr.strip() or "PowerShell command failed")
    return result.stdout.strip()


def get_system_info() -> dict:
    """Return computer name, domain join status, and OS version details.

    Raises RuntimeError if the underlying PowerShell query fails (e.g. not
    running on Windows, or PowerShell unavailable).
    """
    cs_json = _run_powershell(
        "Get-CimInstance Win32_ComputerSystem | "
        "Select-Object Name,Domain,PartOfDomain,Workgroup | ConvertTo-Json -Compress"
    )
    os_json = _run_powershell(
        "Get-CimInstance Win32_OperatingSystem | "
        "Select-Object Caption,Version,BuildNumber,OSArchitecture | ConvertTo-Json -Compress"
    )

    cs = json.loads(cs_json)
    osinfo = json.loads(os_json)

    part_of_domain = bool(cs.get("PartOfDomain"))

    return {
        "computer_name": cs.get("Name"),
        "joined_to_domain": part_of_domain,
        "domain_or_workgroup": cs.get("Domain") if part_of_domain else cs.get("Workgroup"),
        "os_name": osinfo.get("Caption"),
        "os_version": osinfo.get("Version"),
        "os_build": osinfo.get("BuildNumber"),
        "os_architecture": osinfo.get("OSArchitecture"),
    }
