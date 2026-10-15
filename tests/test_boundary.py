"""The Windows boundary: PowerShell, ping, nbtstat, arp. Everything is mocked
at run_hidden/run_powershell, so these run anywhere."""
import json
import subprocess

import pytest

from dhcp_inspector import ad_utils, checks, dhcp_leases, process_utils, software


class Proc:
    def __init__(self, out="", rc=0, err=""):
        self.stdout, self.returncode, self.stderr = out, rc, err


def patch_ps(monkeypatch, module, out="", rc=0, err="", capture=None):
    def fake(script, timeout=None, env=None):
        if capture is not None:
            capture.update(script=script, env=env, timeout=timeout)
        return Proc(out, rc, err)
    monkeypatch.setattr(module, "run_powershell", fake)


# --- text parsers ---------------------------------------------------------

def test_nbtstat_name_ignores_localised_status_column():
    en = "    A-C14-PROV     <00>  UNIQUE      Registered\n    CORP  <00>  GROUP  Registered"
    th = "    V-D35-MMI-03  <00>  UNIQUE      ลงทะเบียนแล้ว"
    assert checks._NBT_NAME.search(en).group(1) == "A-C14-PROV"   # not the GROUP entry
    assert checks._NBT_NAME.search(th).group(1) == "V-D35-MMI-03"
    assert checks._NBT_NAME.search("Host not found.") is None


def test_arp_mac_ignores_localised_type_column():
    en = "  10.20.30.5            00-11-22-33-44-55     dynamic"
    th = "  10.20.30.5            00-11-22-33-44-55     ไดนามิก"
    assert checks._ARP_MAC.search(en).group(1) == "00-11-22-33-44-55"
    assert checks._ARP_MAC.search(th).group(1) == "00-11-22-33-44-55"
    assert checks._ARP_MAC.search("No ARP Entries Found") is None


def test_netbios_and_arp_are_windows_only(monkeypatch):
    monkeypatch.setattr(checks.sys, "platform", "linux")
    assert checks.netbios_name("10.0.0.1") is None
    assert checks.arp_mac("10.0.0.1") is None


# --- resolve_and_ping -----------------------------------------------------

def test_ip_target_names_via_ptr_and_skips_netbios(monkeypatch):
    monkeypatch.setattr(checks, "_ping", lambda ip, t: True)
    monkeypatch.setattr(checks.socket, "gethostbyaddr", lambda ip: ("pc-07.corp.local", [], []))
    monkeypatch.setattr(checks, "netbios_name", lambda ip: pytest.fail("PTR hit must not call NetBIOS"))
    monkeypatch.setattr(checks, "arp_mac", lambda ip: "aa-aa-aa-aa-aa-aa")
    r = checks.resolve_and_ping("10.20.30.5")
    assert r == {"ip": "10.20.30.5", "dns_ok": True, "ping": True,
                 "resolved_name": "pc-07.corp.local", "arp_mac": "aa-aa-aa-aa-aa-aa", "error": None}


def test_ptr_miss_falls_back_to_netbios(monkeypatch):
    monkeypatch.setattr(checks, "_ping", lambda ip, t: True)
    monkeypatch.setattr(checks.socket, "gethostbyaddr", lambda ip: (_ for _ in ()).throw(OSError))
    monkeypatch.setattr(checks, "netbios_name", lambda ip: "A-C14-PROV")
    monkeypatch.setattr(checks, "arp_mac", lambda ip: None)
    assert checks.resolve_and_ping("10.20.30.5")["resolved_name"] == "A-C14-PROV"


def test_dead_address_costs_no_name_or_arp_lookups(monkeypatch):
    monkeypatch.setattr(checks, "_ping", lambda ip, t: False)
    for fn in ("netbios_name", "arp_mac"):
        monkeypatch.setattr(checks, fn, lambda ip: pytest.fail("looked up a dead address"))
    monkeypatch.setattr(checks.socket, "gethostbyaddr", lambda ip: pytest.fail("PTR for a dead address"))
    r = checks.resolve_and_ping("10.20.30.99")
    assert r["ping"] is False and r["resolved_name"] is None and r["dns_ok"] is True


def test_hostname_target_resolves_forward(monkeypatch):
    monkeypatch.setattr(checks.socket, "gethostbyname", lambda n: "10.0.0.1")
    monkeypatch.setattr(checks, "_ping", lambda ip, t: True)
    monkeypatch.setattr(checks, "arp_mac", lambda ip: None)
    assert checks.resolve_and_ping("PC-01")["ip"] == "10.0.0.1"


def test_unresolvable_hostname_is_no_dns(monkeypatch):
    monkeypatch.setattr(checks.socket, "gethostbyname", lambda n: (_ for _ in ()).throw(OSError))
    r = checks.resolve_and_ping("GONE")
    assert r["dns_ok"] is False and r["ping"] is False


@pytest.mark.parametrize("platform, stdout, rc, expected", [
    ("win32", "Reply from 10.0.0.1: bytes=32 time<1ms TTL=128", 0, True),
    ("win32", "Reply from 10.0.0.9: Destination host unreachable.", 0, False),  # exits 0 on Windows!
    ("win32", "Request timed out.", 1, False),
    ("linux", "64 bytes from 10.0.0.1", 0, True),
])
def test_ping_result_parsing(monkeypatch, platform, stdout, rc, expected):
    monkeypatch.setattr(checks.sys, "platform", platform)
    monkeypatch.setattr(checks, "run_hidden", lambda *a, **k: Proc(stdout, rc))
    assert checks._ping("10.0.0.1", 1000) is expected


def test_ping_timeout_is_a_failed_ping(monkeypatch):
    def boom(*a, **k):
        raise subprocess.TimeoutExpired("ping", 1)
    monkeypatch.setattr(checks, "run_hidden", boom)
    assert checks._ping("10.0.0.1", 1000) is False


# --- check_computer -------------------------------------------------------

WMI_OK = {"ComputerName": "PC-1", "WmiOk": True, "Name": "PC-1.corp.local", "UserName": "CORP\\tunva",
          "Mac": "00:1A:2B:3C:4D:5E", "PartOfDomain": True, "Domain": "corp.local",
          "DHCPServer": "10.0.0.254", "OSVersion": "Windows 11 Pro", "LastBoot": "2026-10-13T08:00:00.1234567+07:00",
          "LastPatch": "2026-10-01T00:00:00.0000000+07:00", "RecentHotfixes": "KB1 (2026-10-01)", "FirstError": "x"}


def test_check_computer_maps_every_field(monkeypatch):
    patch_ps(monkeypatch, checks, json.dumps(WMI_OK))
    r = checks.check_computer("PC-1")
    assert r["wmi_ok"] and r["wmi_name"] == "PC-1.corp.local" and r["user_login"] == "CORP\\tunva"
    assert r["wmi_mac"] == "00:1A:2B:3C:4D:5E" and r["dhcp_server"] == "10.0.0.254"
    assert r["last_patch"].startswith("2026-10-01") and r["recent_hotfixes"] == "KB1 (2026-10-01)"
    assert r["error"] is None, "a sub-query hiccup on a reachable machine is not an error"


def test_check_computer_reports_error_when_wmi_never_answered(monkeypatch):
    patch_ps(monkeypatch, checks, json.dumps({"ComputerName": "PC-1", "WmiOk": False, "FirstError": "Access is denied."}))
    r = checks.check_computer("PC-1")
    assert not r["wmi_ok"] and r["error"] == "Access is denied."


@pytest.mark.parametrize("kwargs, message", [
    (dict(out="", rc=1, err="boom"), "boom"),
    (dict(out="", rc=0), "No response"),
    (dict(out="not json"), "Unexpected output"),
])
def test_check_computer_failures_never_raise(monkeypatch, kwargs, message):
    patch_ps(monkeypatch, checks, **kwargs)
    r = checks.check_computer("PC-1")
    assert r["wmi_ok"] is False and message in r["error"]


def test_check_computer_timeout(monkeypatch):
    def boom(*a, **k):
        raise subprocess.TimeoutExpired("powershell", 5)
    monkeypatch.setattr(checks, "run_powershell", boom)
    assert "Timed out after 5s" in checks.check_computer("PC-1", timeout=5)["error"]


def test_computer_name_is_quoted_and_password_stays_out_of_the_script(monkeypatch):
    seen = {}
    patch_ps(monkeypatch, checks, json.dumps(WMI_OK), capture=seen)
    checks.check_computer("O'Brien-PC", credential=("CORP\\svc", "s3cret!"))
    assert seen["script"].startswith("$ComputerName = 'O''Brien-PC'\n")
    assert "s3cret!" not in seen["script"] and "CORP\\svc" not in seen["script"]
    assert seen["env"]["DHCPINSPECT_PASS"] == "s3cret!" and seen["env"]["DHCPINSPECT_USER"] == "CORP\\svc"


def test_no_credential_inherits_the_environment(monkeypatch):
    seen = {}
    patch_ps(monkeypatch, checks, json.dumps(WMI_OK), capture=seen)
    checks.check_computer("PC-1")
    assert seen["env"] is None
    assert checks._credential_env(("", "x")) is None


def test_check_script_pins_the_things_that_broke_before():
    script = checks._CHECK_SCRIPT
    assert "-Protocol Dcom" in script or "New-CimSessionOption -Protocol Dcom" in script
    assert "Win32_QuickFixEngineering" in script and "-as [DateTime]" in script
    assert "$result.UserName" in script and "$result.Mac" in script
    assert checks._SESSION_PREAMBLE in script


# --- software -------------------------------------------------------------

def app(name, version="1.0", publisher="Pub", date="20260901", scope="Machine"):
    return {"Name": name, "Version": version, "Publisher": publisher, "InstallDate": date, "Scope": scope}


def run_software(monkeypatch, payload, **kw):
    patch_ps(monkeypatch, software, json.dumps(payload), **kw)
    return software.list_software("PC-1", timeout=5)


def test_software_script_never_uses_win32_product():
    script = software._SOFTWARE_SCRIPT
    assert "Win32_Product" not in script
    assert "StdRegProv" in script and "WOW6432Node" in script
    assert "-Depth 4" in script, "default depth 2 flattens records to a type name"
    assert software._SESSION_PREAMBLE in script


def test_software_normalises_dedupes_and_sorts(monkeypatch):
    r = run_software(monkeypatch, {"Ok": True, "Partial": False, "FirstError": "blip", "Software": [
        app("  Google Chrome ", "129", "Google LLC"),
        app("7-Zip", "24.08", "Igor Pavlov", date=None),
        app("Google Chrome", "129", "google llc", scope="Machine (32-bit)"),   # same app, other registry view
        app("", "1"),                                                          # nameless: dropped
        app("Zoom", date="9/1/2026", scope="Per-user"),
    ]})
    assert [a["name"] for a in r["apps"]] == ["7-Zip", "Google Chrome", "Zoom"]
    assert r["apps"][1]["install_date"] == "2026-09-01"
    assert r["apps"][2]["install_date"] == "9/1/2026"      # non-YYYYMMDD left alone
    assert r["ok"] and r["error"] is None


def test_software_single_app_arrives_as_object_not_list(monkeypatch):
    r = run_software(monkeypatch, {"Ok": True, "Software": app("Solo")})
    assert [a["name"] for a in r["apps"]] == ["Solo"]


def test_software_partial_keeps_apps_and_the_error(monkeypatch):
    r = run_software(monkeypatch, {"Ok": True, "Partial": True, "FirstError": "RPC unavailable",
                                   "Software": [app("Chrome")]})
    assert r["ok"] and r["partial"] and r["error"] == "RPC unavailable" and len(r["apps"]) == 1


def test_software_failure_modes(monkeypatch):
    assert run_software(monkeypatch, {"Ok": False, "FirstError": "Access is denied."})["error"] == "Access is denied."
    patch_ps(monkeypatch, software, "", 1, "boom")
    assert software.list_software("PC-1")["error"] == "boom"
    patch_ps(monkeypatch, software, "not json")
    assert software.list_software("PC-1")["error"] == "Unexpected output from software script"


def test_software_timeout_and_credentials(monkeypatch):
    def boom(*a, **k):
        raise subprocess.TimeoutExpired("powershell", 5)
    monkeypatch.setattr(software, "run_powershell", boom)
    assert software.list_software("PC-1", timeout=5)["error"] == "Timed out after 5s"

    seen = {}
    patch_ps(monkeypatch, software, json.dumps({"Ok": False}), capture=seen)
    software.list_software("O'Brien", credential=("CORP\\svc", "pw!"), timeout=5)
    assert seen["script"].startswith("$ComputerName = 'O''Brien'\n") and "pw!" not in seen["script"]
    assert seen["env"]["DHCPINSPECT_PASS"] == "pw!"


# --- DHCP leases ----------------------------------------------------------

def test_lease_script_targets_named_server_and_escapes():
    assert "ComputerName = 'dhcp01'" in dhcp_leases._build_script("dhcp01")
    assert "ComputerName = 'a''b'" in dhcp_leases._build_script("a'b")
    assert dhcp_leases._build_script("").startswith("$ServerArg = @{}")


def test_lease_parsing(monkeypatch):
    patch_ps(monkeypatch, dhcp_leases, json.dumps([
        {"IP": "10.0.0.5", "Name": "A-C14.corp.local", "Mac": "00-1a-2b-3c-4d-5e"},
        {"IP": "10.0.0.6", "Name": "", "Mac": "00-11-22-33-44-55"},
        {"IP": None, "Name": "orphan"}]))
    leases = dhcp_leases.load_leases("dhcp01")
    assert leases["10.0.0.5"] == {"name": "A-C14.corp.local", "mac": "00-1a-2b-3c-4d-5e"}
    assert leases["10.0.0.6"]["name"] is None and len(leases) == 2


def test_lease_edge_cases(monkeypatch):
    patch_ps(monkeypatch, dhcp_leases, json.dumps({"IP": "10.0.0.9", "Name": "PC-9", "Mac": "aa"}))
    assert dhcp_leases.load_leases("d")["10.0.0.9"]["name"] == "PC-9"      # single lease, not a list
    patch_ps(monkeypatch, dhcp_leases, "")
    assert dhcp_leases.load_leases("d") == {}
    patch_ps(monkeypatch, dhcp_leases, "", 1, "not recognized")
    with pytest.raises(RuntimeError, match="not recognized"):
        dhcp_leases.load_leases("d")
    patch_ps(monkeypatch, dhcp_leases, "garbage")
    with pytest.raises(RuntimeError, match="Unexpected output"):
        dhcp_leases.load_leases("d")


# --- AD -------------------------------------------------------------------

def test_domain_from_distinguished_name():
    assert ad_utils._domain_from_dn("CN=PC1,OU=Lab,DC=corp,DC=example,DC=com") == "corp.example.com"
    assert ad_utils._domain_from_dn(None) is None and ad_utils._domain_from_dn("CN=x") is None


def test_ad_filter_is_escaped_and_asks_for_the_needed_properties():
    script = ad_utils._build_script("o'brien")
    assert "*o''brien*" in script
    for prop in ("PasswordLastSet", "LastLogonTimestamp", "OperatingSystem", "DistinguishedName"):
        assert prop in script
    assert "-Filter \"*\"" in ad_utils._build_script("")


def test_load_ad_computers(monkeypatch):
    patch_ps(monkeypatch, ad_utils, json.dumps({"Name": "PC-1", "DistinguishedName": "CN=PC-1,DC=corp,DC=local",
                                                "OperatingSystem": "Windows 10", "Enabled": True,
                                                "PasswordLastSet": "2026-10-01T00:00:00.0000000+07:00",
                                                "LastLogon": None}))
    (rec,) = ad_utils.load_ad_computers()               # one computer is a bare object
    assert rec["name"] == "PC-1" and rec["domain"] == "corp.local" and rec["enabled"] is True
    patch_ps(monkeypatch, ad_utils, "", 1, "module missing")
    with pytest.raises(RuntimeError, match="module missing"):
        ad_utils.load_ad_computers()
    patch_ps(monkeypatch, ad_utils, "")
    assert ad_utils.load_ad_computers() == []


# --- process helpers ------------------------------------------------------

def test_run_powershell_pins_utf8_both_ways(monkeypatch):
    captured = {}
    monkeypatch.setattr(process_utils.subprocess, "run",
                        lambda args, **kw: captured.update(args=args, kw=kw) or Proc())
    process_utils.run_powershell("Get-Thing")
    assert captured["kw"]["encoding"] == "utf-8" and captured["kw"]["errors"] == "replace"
    assert "[Console]::OutputEncoding" in captured["args"][-1] and captured["args"][-1].endswith("Get-Thing")
