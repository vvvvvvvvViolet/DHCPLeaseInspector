"""Turns a raw check result into an uptime string, a score, and a status."""
from datetime import datetime

_MAX_HEALTHY_UPTIME_DAYS = 30


def _parse_last_boot(last_boot_iso: str | None) -> datetime | None:
    if not last_boot_iso:
        return None
    try:
        return datetime.fromisoformat(last_boot_iso)
    except ValueError:
        return None


def compute_uptime_str(last_boot_iso: str | None) -> str:
    last_boot = _parse_last_boot(last_boot_iso)
    if last_boot is None:
        return "-"
    now = datetime.now(last_boot.tzinfo) if last_boot.tzinfo else datetime.now()
    delta = now - last_boot
    hours = delta.seconds // 3600
    return f"{delta.days}d {hours}h"


def compute_score(check: dict) -> tuple[int, str]:
    """Returns (score 0-100, status label) from a check_computer() result."""
    if not check.get("ping"):
        return 0, "Offline"

    score = 25  # reachable

    if check.get("part_of_domain"):
        score += 25

    if check.get("wsus"):
        score += 25

    last_boot = _parse_last_boot(check.get("last_boot"))
    if last_boot is not None:
        now = datetime.now(last_boot.tzinfo) if last_boot.tzinfo else datetime.now()
        if (now - last_boot).days < _MAX_HEALTHY_UPTIME_DAYS:
            score += 25

    status = "Ready" if score >= 75 else "Needs Attention"
    return score, status
