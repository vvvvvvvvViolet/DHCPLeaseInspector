"""Checks the status of the Windows DHCP Client service."""
import subprocess


def get_dhcp_client_status() -> dict:
    """Return the Windows 'Dhcp' service state and start mode."""
    result = subprocess.run(
        [
            "powershell", "-NoProfile", "-NonInteractive", "-Command",
            "Get-Service -Name Dhcp | Select-Object Status,StartType | "
            "ForEach-Object { \"$($_.Status)|$($_.StartType)\" }",
        ],
        capture_output=True,
        text=True,
        timeout=15,
    )
    if result.returncode != 0:
        raise RuntimeError(result.stderr.strip() or "Could not query the Dhcp service")

    output = result.stdout.strip()
    if not output:
        raise RuntimeError("Dhcp service not found")

    status, start_type = output.split("|", 1)
    return {"status": status.strip(), "start_type": start_type.strip()}
