"""Derives uptime, domain health, and an overall status from a check result."""
import re
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


def format_last_patch(last_patch_iso: str | None, recent_hotfixes: str | None) -> tuple[str, str]:
    """Returns (cell text, tooltip). Tooltip lists the recent hotfix IDs."""
    patch = _parse_dt(last_patch_iso)
    if patch is None:
        return "-", ""
    days = (_now_like(patch) - patch).days
    tip = f"{days} day(s) ago"
    if recent_hotfixes:
        tip += f"\nRecent: {recent_hotfixes}"
    return patch.strftime("%Y-%m-%d"), tip


def patch_overdue(check: dict) -> bool:
    """True when the newest installed hotfix is older than the threshold.

    Unknown patch date (WMI unavailable) is never flagged — we don't guess.
    """
    patch = _parse_dt(check.get("last_patch"))
    if patch is None:
        return False
    age_days = (_now_like(patch) - patch).days
    return age_days > config.get_settings().stale_patch_days


def format_mac(check: dict) -> tuple[str, str]:
    """Pick the best MAC for a row and normalise it. Returns (text, tooltip).

    The three sources disagree on punctuation and case — WMI gives
    `00:1A:2B:…`, a DHCP ClientId `00-11-22-…` or bare hex, ARP
    `00-11-22-…` — so they're all rendered as uppercase dash-separated to
    stay comparable. The tooltip records which source answered, since they
    differ in trustworthiness.
    """
    for value, source in ((check.get("wmi_mac"), "reported by the host over WMI"),
                          (check.get("lease_mac"), "from the DHCP lease"),
                          (check.get("arp_mac"), "from this machine's ARP cache")):
        if not value:
            continue
        hex_digits = re.sub(r"[^0-9A-Fa-f]", "", value)
        if len(hex_digits) != 12:
            # Not a plain 48-bit address (some DHCP ClientIds carry a type
            # prefix) — show it as-is rather than mangling it.
            return value, source
        pairs = [hex_digits[i:i + 2] for i in range(0, 12, 2)]
        return "-".join(pairs).upper(), source
    return "-", ""


def format_user_login(check: dict) -> tuple[str, str]:
    """Returns (cell text, tooltip) for the logged-on user."""
    user = (check.get("user_login") or "").strip()
    if not user:
        return "-", ""
    # Win32_ComputerSystem reports DOMAIN\user; the account is the useful
    # half in a single-domain fleet, so lead with it and keep the full
    # value in the tooltip.
    if "\\" in user:
        domain, _, account = user.partition("\\")
        return account, f"{user} (domain {domain})"
    return user, user


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

    # A live host with no matching AD computer account — an unmanaged or
    # rogue device. Only reported when AD data was loaded to compare against.
    if check.get("in_ad") is False:
        return "Not in AD"

    # A domain problem is more fundamental than a patch lag, so it wins.
    if domain_health(check) in ("Disabled", "Stale", "Not Joined"):
        return "Domain Issue"
    if patch_overdue(check):
        return "Patch Overdue"
    return "Ready"
