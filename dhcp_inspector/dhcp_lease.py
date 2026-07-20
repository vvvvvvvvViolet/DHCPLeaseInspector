"""Parses `ipconfig /all` to report the active DHCP lease per adapter."""
import re
import subprocess


_ADAPTER_HEADER = re.compile(r"^(?!\s)(.+ adapter .+):\s*$", re.IGNORECASE)
_FIELD = re.compile(r"^\s*([A-Za-z0-9 .\-()/]+?)\s*(?:\.\s*)*:\s*(.*)$")


def _run_ipconfig() -> str:
    result = subprocess.run(
        ["ipconfig", "/all"],
        capture_output=True,
        text=True,
        timeout=15,
    )
    if result.returncode != 0:
        raise RuntimeError(result.stderr.strip() or "ipconfig failed")
    return result.stdout


def get_dhcp_leases() -> list[dict]:
    """Return a list of adapters that currently have DHCP enabled.

    Each entry contains: adapter, dhcp_enabled, ipv4_address, subnet_mask,
    dhcp_server, lease_obtained, lease_expires.
    """
    output = _run_ipconfig()
    lines = output.splitlines()

    adapters = []
    current = None

    for line in lines:
        header_match = _ADAPTER_HEADER.match(line)
        if header_match:
            current = {"adapter": header_match.group(1).strip()}
            adapters.append(current)
            continue

        if current is None:
            continue

        field_match = _FIELD.match(line)
        if not field_match:
            continue

        key = field_match.group(1).strip().lower()
        value = field_match.group(2).strip()

        if "dhcp enabled" in key:
            current["dhcp_enabled"] = value.lower() == "yes"
        elif key.startswith("ipv4 address"):
            current["ipv4_address"] = value.split("(")[0].strip()
        elif "subnet mask" in key:
            current["subnet_mask"] = value
        elif key == "dhcp server":
            current["dhcp_server"] = value
        elif "lease obtained" in key:
            current["lease_obtained"] = value
        elif "lease expires" in key:
            current["lease_expires"] = value

    return [a for a in adapters if a.get("dhcp_enabled") and a.get("ipv4_address")]
