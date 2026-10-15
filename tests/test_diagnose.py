import json
import subprocess

import pytest
from conftest import wait_for

from dhcp_inspector import checks, diagnose
from dhcp_inspector import diagnose_window as dw
from dhcp_inspector import main_window as mw


class Proc:
    def __init__(self, out="", rc=0, err=""):
        self.stdout, self.returncode, self.stderr = out, rc, err


def ps_steps(*entries):
    return json.dumps([{"Name": n, "Ok": ok, "Ms": ms, "Detail": d, "Error": e}
                       for n, ok, ms, d, e in entries])


ALL_OK = ps_steps(
    ("Open DCOM session", True, 120, "connected", None),
    ("WMI: Win32_ComputerSystem", True, 80, "name=PC-1 domain=corp.local user=CORP\\x", None),
    ("WMI: Win32_OperatingSystem", True, 70, "Windows 11 Pro (last boot 2026-10-13 08:00)", None),
    ("WMI: Win32_NetworkAdapterConfiguration", True, 90, "1 adapter(s); mac=00:1A:2B:3C:4D:5E dhcp=10.0.0.254", None),
    ("WMI: Win32_QuickFixEngineering", True, 300, "42 hotfix(es)", None),
    ("Registry read (StdRegProv)", True, 60, "180 uninstall key(s) readable", None),
)


@pytest.fixture
def healthy(monkeypatch):
    """A reachable machine: every local probe passes; PowerShell is mocked."""
    monkeypatch.setattr(diagnose.socket, "gethostbyname", lambda n: "10.0.0.5")
    monkeypatch.setattr(diagnose.socket, "gethostbyaddr", lambda ip: ("pc-1.corp.local", [], []))
    monkeypatch.setattr(checks, "_ping", lambda ip, t: True)
    monkeypatch.setattr(diagnose, "_tcp", lambda ip, port, timeout=3.0: (True, "connected"))
    monkeypatch.setattr(checks, "netbios_name", lambda ip: "PC-1")
    monkeypatch.setattr(checks, "arp_mac", lambda ip: "00-1a-2b-3c-4d-5e")
    calls = []
    def fake_ps(script, timeout=None, env=None):
        calls.append({"script": script, "env": env})
        return Proc(ALL_OK)
    monkeypatch.setattr(diagnose, "run_powershell", fake_ps)
    return calls


def by_name(steps):
    return {s["name"]: s for s in steps}


# --- hints ----------------------------------------------------------------

@pytest.mark.parametrize("error, fragment", [
    ("Access is denied.", "administrator"),
    ("... HRESULT 0x80070005", "administrator"),
    ("The user name or password is incorrect.", "Credentials"),
    ("0x8007052E", "wrong"),
    ("The RPC server is unavailable.", "firewall"),
    ("... 0x800706BA ...", "firewall"),
    ("The network path was not found.", "does not resolve"),
    ("Invalid namespace", "repository"),
    ("The operation has timed out", "did not answer in time"),
])
def test_known_errors_get_actionable_hints(error, fragment):
    assert fragment in diagnose.hint_for(error)


def test_unknown_errors_get_no_invented_hint():
    assert diagnose.hint_for("something nobody has seen before") == ""
    assert diagnose.hint_for("") == "" and diagnose.hint_for(None) == ""


# --- a healthy machine ----------------------------------------------------

def test_healthy_machine_passes_every_required_step(healthy):
    steps = diagnose.diagnose("PC-1")
    assert [s["name"] for s in steps][:2] == ["DNS lookup", "Ping"]
    assert [s["name"] for s in steps][-6:] == diagnose.REMOTE_STEPS
    counts = diagnose.summarise(steps)
    assert counts == {"passed": 9, "failed": 0, "skipped": 0, "info": 4}
    assert by_name(steps)["WMI: Win32_QuickFixEngineering"]["detail"] == "42 hotfix(es)"
    assert len(healthy) == 1


def test_steps_are_streamed_as_they_complete(healthy):
    seen = []
    result = diagnose.diagnose("PC-1", on_step=seen.append)
    assert seen == result


def test_an_ip_target_skips_dns_instead_of_failing_it(healthy):
    steps = diagnose.diagnose("10.0.0.5")
    dns = by_name(steps)["DNS lookup"]
    assert dns["ok"] is None and "IP address" in dns["detail"]


# --- failures at each layer ----------------------------------------------

def test_unresolvable_name_skips_everything_else(monkeypatch, healthy):
    monkeypatch.setattr(diagnose.socket, "gethostbyname", lambda n: (_ for _ in ()).throw(OSError("no such host")))
    steps = diagnose.diagnose("GONE")
    assert steps[0]["ok"] is False and "no such host" in steps[0]["detail"] and "IP address" in steps[0]["hint"]
    assert all(s["ok"] is None for s in steps[1:])
    assert healthy == [], "PowerShell must not run without an address"


def test_closed_rpc_port_skips_wmi_and_never_starts_powershell(monkeypatch, healthy):
    monkeypatch.setattr(diagnose, "_tcp", lambda ip, port, timeout=3.0: (port != 135, "refused" if port == 135 else "connected"))
    steps = by_name(diagnose.diagnose("PC-1"))
    assert steps["TCP 135 (RPC endpoint mapper)"]["ok"] is False
    assert "firewall" in steps["TCP 135 (RPC endpoint mapper)"]["hint"].lower() or "DCOM" in steps["TCP 135 (RPC endpoint mapper)"]["hint"]
    for name in diagnose.REMOTE_STEPS:
        assert steps[name]["ok"] is None and "135" in steps[name]["detail"]
    assert healthy == []


def test_ping_failure_alone_is_reported_but_does_not_stop_wmi(monkeypatch, healthy):
    # ICMP is often blocked on machines that answer WMI fine.
    monkeypatch.setattr(checks, "_ping", lambda ip, t: False)
    steps = by_name(diagnose.diagnose("PC-1"))
    assert steps["Ping"]["ok"] is False and "not conclusive" in steps["Ping"]["detail"]
    assert steps["WMI: Win32_ComputerSystem"]["ok"] is True and len(healthy) == 1


def test_informational_failures_do_not_count_as_failed(monkeypatch, healthy):
    monkeypatch.setattr(diagnose.socket, "gethostbyaddr", lambda ip: (_ for _ in ()).throw(OSError))
    monkeypatch.setattr(checks, "netbios_name", lambda ip: None)
    monkeypatch.setattr(checks, "arp_mac", lambda ip: None)
    steps = diagnose.diagnose("PC-1")
    assert diagnose.summarise(steps)["failed"] == 0
    assert all(s["optional"] for s in steps if s["name"] in ("Reverse DNS (PTR)", "NetBIOS name", "MAC from ARP cache"))


def test_denied_session_fails_that_step_and_skips_the_classes_behind_it(monkeypatch, healthy):
    monkeypatch.setattr(diagnose, "run_powershell", lambda *a, **k: Proc(ps_steps(
        ("Open DCOM session", False, 2300, None, "Access is denied. HRESULT 0x80070005"))))
    steps = by_name(diagnose.diagnose("PC-1"))
    session = steps["Open DCOM session"]
    assert session["ok"] is False and "Access is denied" in session["detail"] and "administrator" in session["hint"]
    for name in diagnose.REMOTE_STEPS[1:]:
        assert steps[name]["ok"] is None and "no DCOM session" in steps[name]["detail"]


def test_one_wmi_class_failing_does_not_hide_the_others(monkeypatch, healthy):
    monkeypatch.setattr(diagnose, "run_powershell", lambda *a, **k: Proc(ps_steps(
        ("Open DCOM session", True, 100, "connected", None),
        ("WMI: Win32_ComputerSystem", True, 50, "name=PC-1", None),
        ("WMI: Win32_OperatingSystem", True, 50, "Win11", None),
        ("WMI: Win32_NetworkAdapterConfiguration", True, 50, "1 adapter(s)", None),
        ("WMI: Win32_QuickFixEngineering", False, 15000, None, "Invalid namespace  0x8004100E"),
        ("Registry read (StdRegProv)", True, 50, "180 uninstall key(s) readable", None))))
    steps = by_name(diagnose.diagnose("PC-1"))
    assert steps["WMI: Win32_QuickFixEngineering"]["ok"] is False
    assert steps["WMI: Win32_QuickFixEngineering"]["error"].startswith("Invalid namespace")
    assert steps["Registry read (StdRegProv)"]["ok"] is True
    assert diagnose.summarise(list(steps.values()))["failed"] == 1


def test_a_single_step_json_object_is_accepted(monkeypatch, healthy):
    one = json.dumps({"Name": "Open DCOM session", "Ok": False, "Ms": 5, "Detail": None, "Error": "boom"})
    monkeypatch.setattr(diagnose, "run_powershell", lambda *a, **k: Proc(one))
    assert by_name(diagnose.diagnose("PC-1"))["Open DCOM session"]["ok"] is False


@pytest.mark.parametrize("proc, fragment", [
    (Proc("not json", 0, "powershell exploded"), "powershell exploded"),
    (Proc("", 1, ""), "no usable output"),
])
def test_unusable_powershell_output_is_a_failed_session_step(monkeypatch, healthy, proc, fragment):
    monkeypatch.setattr(diagnose, "run_powershell", lambda *a, **k: proc)
    steps = by_name(diagnose.diagnose("PC-1"))
    assert steps["Open DCOM session"]["ok"] is False and fragment in steps["Open DCOM session"]["detail"]
    assert steps["Registry read (StdRegProv)"]["ok"] is None


def test_powershell_timeout_and_missing_powershell_are_reported(monkeypatch, healthy):
    def timeout(*a, **k): raise subprocess.TimeoutExpired("powershell", 5)
    monkeypatch.setattr(diagnose, "run_powershell", timeout)
    s = by_name(diagnose.diagnose("PC-1", remote_timeout=5))["Open DCOM session"]
    assert s["ok"] is False and "5s" in s["detail"]
    def missing(*a, **k): raise FileNotFoundError("powershell")
    monkeypatch.setattr(diagnose, "run_powershell", missing)
    assert "Could not start PowerShell" in by_name(diagnose.diagnose("PC-1"))["Open DCOM session"]["detail"]


def test_a_crashing_probe_is_reported_not_raised(monkeypatch, healthy):
    monkeypatch.setattr(checks, "_ping", lambda ip, t: (_ for _ in ()).throw(RuntimeError("kaboom")))
    ping = by_name(diagnose.diagnose("PC-1"))["Ping"]
    assert ping["ok"] is False


# --- the remote script and credentials ------------------------------------

def test_credentials_travel_in_the_environment_not_the_script(healthy):
    diagnose.diagnose("O'Brien-PC", credential=("CORP\\svc", "s3cret!"))
    call = healthy[0]
    assert call["script"].startswith("$ComputerName = 'O''Brien-PC'\n")
    assert "s3cret!" not in call["script"] and "CORP\\svc" not in call["script"]
    assert call["env"]["DHCPINSPECT_PASS"] == "s3cret!"


def test_remote_script_runs_each_probe_on_its_own():
    script = diagnose._REMOTE_SCRIPT
    assert checks._SESSION_PREAMBLE in script
    assert script.count("Run-Step '") == 5            # each class guarded separately
    assert "-Depth 4" in script and "InputObject @($steps)" in script   # one step still serialises as an array
    for name in diagnose.REMOTE_STEPS:
        assert name in script
    assert "Win32_Product" not in script


# --- the report -----------------------------------------------------------

def test_report_lists_every_step_the_failure_and_what_to_try(monkeypatch, healthy):
    monkeypatch.setattr(diagnose, "run_powershell", lambda *a, **k: Proc(ps_steps(
        ("Open DCOM session", False, 2300, None, "Access is denied."))))
    report = diagnose.format_report("PC-1", diagnose.diagnose("PC-1"))
    assert "Target: PC-1" in report and "Connecting as: the current Windows user" in report
    assert "[FAIL] Open DCOM session" in report and "[OK  ] DNS lookup" in report
    assert "[SKIP] WMI: Win32_OperatingSystem" in report
    assert "What to try:" in report and "administrator" in report


def test_report_never_contains_the_password(healthy):
    steps = diagnose.diagnose("PC-1", credential=("CORP\\svc", "s3cret!"))
    report = diagnose.format_report("PC-1", steps, ("CORP\\svc", "s3cret!"))
    assert "s3cret!" not in report and "alternate account CORP\\svc" in report


def test_clean_report_says_so(healthy):
    report = diagnose.format_report("PC-1", diagnose.diagnose("PC-1"))
    assert "Everything this machine needs" in report and "What to try" not in report


def test_report_keeps_the_raw_error_text(monkeypatch, healthy):
    raw = "Get-CimInstance : Access is denied.\nHRESULT 0x80070005"
    monkeypatch.setattr(diagnose, "run_powershell", lambda *a, **k: Proc(ps_steps(
        ("Open DCOM session", False, 10, None, raw))))
    assert "raw error: Get-CimInstance : Access is denied." in diagnose.format_report("PC-1", diagnose.diagnose("PC-1"))


def test_tcp_probe_reports_refusal_and_timeout(monkeypatch):
    def refuse(*a, **k): raise ConnectionRefusedError("refused")
    monkeypatch.setattr(diagnose.socket, "create_connection", refuse)
    assert diagnose._tcp("10.0.0.1", 135) == (False, "refused")
    def hang(*a, **k): raise diagnose.socket.timeout()
    monkeypatch.setattr(diagnose.socket, "create_connection", hang)
    ok, detail = diagnose._tcp("10.0.0.1", 135, timeout=3)
    assert ok is False and "no answer within 3s" in detail


# --- the window -----------------------------------------------------------

def test_dialog_runs_in_the_background_and_shows_each_step(qapp, healthy):
    dialog = dw.DiagnoseDialog("PC-1")
    dialog.start()
    wait_for(qapp, lambda: not dialog.is_running())
    assert dialog.table.rowCount() == len(diagnose.diagnose("PC-1"))
    assert dialog.run_btn.isEnabled() and dialog.copy_btn.isEnabled()
    assert "9 passed, 0 failed" in dialog.status_label.text()
    dialog.close()


def test_dialog_marks_failures_and_shows_advice(qapp, monkeypatch, healthy):
    monkeypatch.setattr(diagnose, "run_powershell", lambda *a, **k: Proc(ps_steps(
        ("Open DCOM session", False, 2300, None, "Access is denied."))))
    dialog = dw.DiagnoseDialog("PC-1")
    dialog.start()
    wait_for(qapp, lambda: not dialog.is_running())
    rows = {dialog.table.item(r, 0).text(): (dialog.table.item(r, 1).text(), dialog.table.item(r, 0).background().color())
            for r in range(dialog.table.rowCount())}
    assert rows["Open DCOM session"] == ("FAIL", dw._COLOR_FAIL)
    assert rows["WMI: Win32_OperatingSystem"][0] == "Skipped"
    assert rows["Reverse DNS (PTR)"][0] == "OK" and rows["DNS lookup"][0] == "OK"
    assert "What to try" in dialog.advice_label.text() and "administrator" in dialog.advice_label.text()
    dialog.close()


def test_copy_report_puts_the_report_on_the_clipboard(qapp, healthy):
    from PyQt5.QtWidgets import QApplication
    dialog = dw.DiagnoseDialog("PC-1", ("CORP\\svc", "s3cret!"))
    dialog.start()
    wait_for(qapp, lambda: not dialog.is_running())
    dialog.copy_report()
    text = QApplication.clipboard().text()
    assert "Target: PC-1" in text and "s3cret!" not in text
    dialog.close()


def test_empty_target_asks_for_one_and_runs_nothing(qapp, healthy):
    dialog = dw.DiagnoseDialog("")
    dialog.start()
    assert "Enter a computer name" in dialog.status_label.text()
    assert not dialog.is_running() and dialog.table.rowCount() == 0 and healthy == []
    dialog.close()


def test_a_crash_inside_diagnose_still_re_enables_the_button(qapp, monkeypatch):
    monkeypatch.setattr(diagnose, "diagnose", lambda *a, **k: (_ for _ in ()).throw(RuntimeError("kaboom")))
    dialog = dw.DiagnoseDialog("PC-1")
    dialog.start()
    wait_for(qapp, lambda: not dialog.is_running())
    assert dialog.run_btn.isEnabled() and "kaboom" in dialog.table.item(0, 3).text()
    dialog.close()


# --- the main window's button ---------------------------------------------

@pytest.fixture
def window(qapp):
    w = mw.MainWindow()
    yield w
    if w._diagnose_dialog is not None:
        w._diagnose_dialog.close()
    w.close()


def test_diagnose_button_prefills_the_selected_row(qapp, window):
    window.subnet_edit.setText("10.20.30.5-6")
    window.on_load_subnet()
    window.table.selectRow(1)
    window.on_diagnose()
    assert window._diagnose_dialog.target_edit.text() == "10.20.30.6"


def test_diagnose_with_nothing_selected_opens_a_blank_box_to_type_into(qapp, window):
    window.on_diagnose()
    assert window._diagnose_dialog.target_edit.text() == ""


def test_a_running_diagnosis_is_never_replaced(qapp, window, monkeypatch, healthy):
    import threading
    gate = threading.Event()
    monkeypatch.setattr(diagnose, "_tcp", lambda ip, port, timeout=3.0: (gate.wait(5), "connected"))
    window.on_diagnose()
    first = window._diagnose_dialog
    first.target_edit.setText("PC-1")
    first.start()
    wait_for(qapp, first.is_running)
    window.on_diagnose()                       # second click while the first is still running
    assert window._diagnose_dialog is first
    gate.set()
    wait_for(qapp, lambda: not first.is_running())
