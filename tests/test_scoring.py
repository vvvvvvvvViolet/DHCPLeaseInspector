import pytest
from conftest import days_ago, dotnet_days_ago

from dhcp_inspector import config, scoring


# --- timestamps -----------------------------------------------------------

@pytest.mark.parametrize("text", [
    "2026-10-15T08:12:33.1234567+07:00",  # PowerShell ToString("o"), offset
    "2026-10-15T08:12:33.1234567Z",       # ... UTC kind
    "2026-10-15T08:12:33.1234567",        # ... unspecified kind
    "2026-10-15T08:12:33+07:00",
])
def test_parses_powershell_round_trip_timestamps(text):
    # Regression: Python < 3.11 rejects 7 fraction digits and "Z", which
    # silently blanked Uptime/Last Patch and disabled the Stale check.
    parsed = scoring._parse_dt(text)
    assert parsed is not None
    assert (parsed.year, parsed.month, parsed.day, parsed.second) == (2026, 10, 15, 33)


@pytest.mark.parametrize("text", [None, "", "garbage"])
def test_unparseable_timestamp_is_none(text):
    assert scoring._parse_dt(text) is None


def test_uptime_from_powershell_timestamp():
    assert scoring.compute_uptime_str(dotnet_days_ago(2)) == "2d 0h"
    assert scoring.compute_uptime_str(None) == "-"


def test_last_logon_and_patch_formatting():
    text, tip = scoring.format_last_logon(dotnet_days_ago(200))
    assert len(text) == 10 and "200 day" in tip
    assert scoring.format_last_logon(None) == ("-", "")

    text, tip = scoring.format_last_patch(days_ago(10), "KB5031354 (2026-10-05)")
    assert "10 day" in tip and "KB5031354" in tip
    assert scoring.format_last_patch(None, None) == ("-", "")


# --- domain health and status ---------------------------------------------

def test_domain_health():
    assert scoring.domain_health({"ad_password_last_set": dotnet_days_ago(5)}) == "OK"
    assert scoring.domain_health({"ad_password_last_set": dotnet_days_ago(120)}) == "Stale"
    assert scoring.domain_health({"ad_enabled": False, "ad_password_last_set": days_ago(5)}) == "Disabled"
    assert scoring.domain_health({"part_of_domain": False}) == "Not Joined"
    assert scoring.domain_health({"part_of_domain": True}) == "OK"
    assert scoring.domain_health({}) == "Unknown"


def test_stale_threshold_follows_settings():
    check = {"ad_password_last_set": days_ago(50)}
    assert scoring.domain_health(check) == "Stale"           # default 45
    config.save_settings(config.Settings(stale_password_days=60))
    assert scoring.domain_health(check) == "OK"


def test_domain_label():
    assert scoring.domain_label({"ad_domain": "corp.local", "ad_password_last_set": days_ago(3)}) == "corp.local"
    assert scoring.domain_label({"ad_domain": "corp.local", "ad_password_last_set": days_ago(400)}) == "corp.local (Stale)"
    assert scoring.domain_label({"part_of_domain": False}) == "Not Joined"
    # the live WMI domain wins over the AD-recorded one
    assert scoring.domain_label({"domain": "live.local", "ad_domain": "corp.local", "part_of_domain": True}) == "live.local"


def test_patch_overdue():
    assert scoring.patch_overdue({"last_patch": days_ago(10)}) is False
    assert scoring.patch_overdue({"last_patch": dotnet_days_ago(200)}) is True
    assert scoring.patch_overdue({"last_patch": None}) is False   # unknown is never flagged


@pytest.mark.parametrize("check, status", [
    ({"dns_ok": False}, "No DNS"),
    ({"dns_ok": True, "ping": False, "wmi_ok": False}, "Offline"),
    ({"ping": False, "wmi_ok": False, "error": "Access is denied."}, "Error"),
    ({"ping": True, "in_ad": False}, "Not in AD"),
    ({"ping": True, "in_ad": None}, "Ready"),                    # no AD loaded: never guessed
    ({"ping": True, "ad_password_last_set": days_ago(400), "last_patch": days_ago(300)}, "Domain Issue"),
    ({"ping": True, "ad_password_last_set": days_ago(3), "last_patch": days_ago(300)}, "Patch Overdue"),
    ({"ping": True, "ad_password_last_set": days_ago(3), "last_patch": days_ago(3)}, "Ready"),
    ({"ping": False, "wmi_ok": False, "in_ad": False}, "Offline"),  # dead outranks Not in AD
])
def test_status_precedence(check, status):
    assert scoring.compute_status(check) == status


# --- MAC and user login ---------------------------------------------------

@pytest.mark.parametrize("check, text, source", [
    ({"wmi_mac": "00:1a:2b:3c:4d:5e"}, "00-1A-2B-3C-4D-5E", "WMI"),
    ({"lease_mac": "00-11-22-33-44-55"}, "00-11-22-33-44-55", "DHCP lease"),
    ({"arp_mac": "aabbccddeeff"}, "AA-BB-CC-DD-EE-FF", "ARP"),
    ({"wmi_mac": "00:11:22:33:44:55", "lease_mac": "aa-aa-aa-aa-aa-aa", "arp_mac": "bb-bb-bb-bb-bb-bb"},
     "00-11-22-33-44-55", "WMI"),
    ({"lease_mac": "aa-aa-aa-aa-aa-aa", "arp_mac": "bb-bb-bb-bb-bb-bb"}, "AA-AA-AA-AA-AA-AA", "DHCP lease"),
    ({"lease_mac": "01-00-11-22-33-44-55"}, "01-00-11-22-33-44-55", "DHCP lease"),  # odd ClientId kept as-is
])
def test_mac_source_priority_and_normalisation(check, text, source):
    got_text, tip = scoring.format_mac(check)
    assert got_text == text and source in tip


def test_mac_absent():
    assert scoring.format_mac({}) == ("-", "")


@pytest.mark.parametrize("value, text, tip", [
    ("CORP\\tunva", "tunva", "CORP\\tunva (domain CORP)"),
    ("kiosk", "kiosk", "kiosk"),
    (None, "-", ""),
    ("   ", "-", ""),
])
def test_user_login(value, text, tip):
    assert scoring.format_user_login({"user_login": value}) == (text, tip)
