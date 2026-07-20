"""Derives uptime, domain health, and an overall status from a check result."""
from datetime import datetime

from . import config


def _parse_dt(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(value)
    except ValueError:
        return None


def _now_like(other: datetime) -> datetime:
    return datetime.now(other.tzinfo) if other.tzinfo else datetime.now()


def compute_uptime_str(last_boot_iso: str | None) -> str:
    last_boot = _parse_dt(last_boot_iso)
    if last_boot is None:
        return "-"
    delta = _now_like(last_boot) - last_boot
    hours = delta.seconds // 3600
    return f"{delta.days}d {hours}h"


def format_last_logon(last_logon_iso: str | None) -> tuple[str, str]:
    """Returns (cell text, tooltip). ISO date as text so string sort works."""
    logon = _parse_dt(last_logon_iso)
    if logon is None:
        return "-", ""
    days = (_now_like(logon) - logon).days
    return logon.strftime("%Y-%m-%d"), f"{days} day(s) ago (AD-replicated, may lag ~14 days)"


def domain_health(check: dict) -> str:
    """Assess the machine's domain standing purely from AD facts.

    Returns "OK", "Disabled", "Stale", or "Unknown" (no AD data). This does
    not need to reach the machine, so it works even when WMI is blocked.
    A computer-account password much older than the 30-day rotation default
    is a strong signal the machine has fallen off the domain.
    """
    if check.get("ad_enabled") is False:
        return "Disabled"

    pwd_set = _parse_dt(check.get("ad_password_last_set"))
    if pwd_set is not None:
        age_days = (_now_like(pwd_set) - pwd_set).days
        if age_days > config.get_settings().stale_password_days:
            return "Stale"
        return "OK"

    # Live WMI can still confirm domain membership when AD data is absent.
    if check.get("part_of_domain") is True:
        return "OK"
    if check.get("part_of_domain") is False:
        return "Not Joined"
    return "Unknown"


def domain_label(check: dict) -> str:
    """Text for the Domain column: the domain name plus a health note."""
    if check.get("part_of_domain") is False:
        return "Not Joined"
    domain = check.get("domain") or check.get("ad_domain")

    health = domain_health(check)
    base = domain or "-"
    if health in ("Disabled", "Stale", "Not Joined"):
        return f"{base} ({health})"
    return base


def compute_status(check: dict) -> str:
    """Overall row status combining DNS, reachability, and domain health."""
    if check.get("dns_ok") is False:
        return "No DNS"

    reachable = check.get("ping") or check.get("wmi_ok")
    if not reachable:
        return "Error" if check.get("error") else "Offline"

    if domain_health(check) in ("Disabled", "Stale", "Not Joined"):
        return "Domain Issue"
    return "Ready"
