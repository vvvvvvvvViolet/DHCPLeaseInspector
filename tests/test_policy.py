import zipfile

import pytest
from openpyxl import load_workbook

from dhcp_inspector import export_excel
from dhcp_inspector import policy as sp
from dhcp_inspector import software_window as sww
from dhcp_inspector.policy import Policy


def app(name, version="1.0"):
    return {"name": name, "version": version, "publisher": "Pub", "install_date": "2026-09-01", "scope": "Machine"}


def result(computer, apps, ok=True, partial=False, error=None):
    return {"computer": computer, "ok": ok, "partial": partial, "error": error, "apps": apps}


# --- rule parsing and matching --------------------------------------------

def test_parse_rules_drops_blanks_comments_and_duplicates_keeping_order():
    text = "  AnyDesk \n\n# remote tools\nTeamViewer\nanydesk\n   \nuTorrent"
    assert sp.parse_rules(text) == ["AnyDesk", "TeamViewer", "uTorrent"]
    assert sp.parse_rules("") == [] and sp.parse_rules(None) == []


@pytest.mark.parametrize("rule, name, expected", [
    ("teamviewer", "TeamViewer 15 Host", True),            # substring, any case
    ("TEAMVIEWER", "teamviewer", True),
    ("anydesk*", "AnyDesk", True),
    ("microsoft * 2019", "Microsoft SQL Server 2019", True),
    ("microsoft * 2019", "Microsoft SQL Server 2017", False),
    ("sophos", "Microsoft Defender", False),
    ("Visual C++ 2015 (x64)", "Microsoft Visual C++ 2015 (x64) Redistributable", True),  # literal ()+
    ("c++", "C Sharp", False),
    ("[a-z]", "abc", False),                                # brackets are not a character class
    ("a.c", "abc", False),                                  # "." is not a wildcard
    ("", "anything", True),                                 # blank rules never reach here (parse drops them)
])
def test_rule_matching(rule, name, expected):
    assert sp.matches(rule, name) is expected


# --- evaluation -----------------------------------------------------------

POLICY = Policy(forbidden=["AnyDesk", "uTorrent"], required=["Sophos"])


def test_compliant_machine():
    v = sp.evaluate(result("A", [app("Sophos Endpoint"), app("Google Chrome")]), POLICY)
    assert v == {"status": "Compliant", "forbidden": [], "missing": []}


def test_forbidden_software_is_a_violation_and_names_the_app():
    r = result("A", [app("Sophos Endpoint"), app("AnyDesk 8", "8.0.1")])
    v = sp.evaluate(r, POLICY)
    assert v["status"] == "Violation" and v["missing"] == []
    assert [(rule, a["name"]) for rule, a in v["forbidden"]] == [("AnyDesk", "AnyDesk 8")]


def test_missing_required_software_is_a_violation():
    v = sp.evaluate(result("A", [app("Google Chrome")]), POLICY)
    assert v["status"] == "Violation" and v["missing"] == ["Sophos"]


def test_failed_scan_is_unknown_not_missing():
    # We don't know what is installed, so we must not claim Sophos is absent.
    v = sp.evaluate(result("A", [], ok=False, error="Access is denied."), POLICY)
    assert v == {"status": "Unknown", "forbidden": [], "missing": []}


def test_partial_list_never_claims_missing_but_still_reports_forbidden_it_saw():
    partial = result("A", [app("Google Chrome")], partial=True)
    assert sp.evaluate(partial, POLICY) == {"status": "Unknown", "forbidden": [], "missing": []}
    seen = result("A", [app("uTorrent")], partial=True)
    v = sp.evaluate(seen, POLICY)
    assert v["status"] == "Violation" and v["missing"] == [] and len(v["forbidden"]) == 1


def test_forbidden_only_policy_on_a_complete_clean_list_is_compliant():
    assert sp.evaluate(result("A", [app("Chrome")]), Policy(forbidden=["AnyDesk"]))["status"] == "Compliant"


def test_one_app_matching_two_rules_is_reported_for_each():
    v = sp.evaluate(result("A", [app("AnyDesk Tool")]), Policy(forbidden=["anydesk", "desk"]))
    assert sorted(rule for rule, _ in v["forbidden"]) == ["anydesk", "desk"]


# --- storage --------------------------------------------------------------

def test_policy_round_trips_and_keeps_non_ascii():
    sp.save_policy(Policy(forbidden=["AnyDesk", "โปรแกรมต้องห้าม"], required=["Sophos"]))
    loaded = sp.load_policy()
    assert loaded.forbidden == ["AnyDesk", "โปรแกรมต้องห้าม"] and loaded.required == ["Sophos"]


def test_missing_or_corrupt_policy_file_means_no_rules():
    assert sp.load_policy().empty
    sp._policy_path().write_text("{nope", encoding="utf-8")
    assert sp.load_policy().empty
    sp._policy_path().write_text("[1, 2]", encoding="utf-8")     # valid JSON, wrong shape
    assert sp.load_policy().empty


def test_loading_normalises_a_hand_edited_file():
    sp._policy_path().write_text('{"forbidden": ["  AnyDesk ", "anydesk", ""], "required": []}', encoding="utf-8")
    assert sp.load_policy().forbidden == ["AnyDesk"]


# --- Excel ----------------------------------------------------------------

RESULTS = [
    result("PC-A", [app("Sophos Endpoint"), app("Google Chrome")]),
    result("PC-B", [app("Google Chrome"), app("AnyDesk 8", "8.0.1")]),
    result("PC-C", [app("Sophos Endpoint"), app("uTorrent", "3.5")]),
    result("PC-D", [], ok=False, error="Access is denied."),
]


def export(tmp_path, results=RESULTS, policy=POLICY):
    path = tmp_path / "sw.xlsx"
    export_excel.export_software(str(path), results, policy)
    return path, load_workbook(path)


def test_export_without_rules_keeps_the_original_layout(tmp_path):
    for policy in (None, Policy()):
        _, wb = export(tmp_path, policy=policy)
        assert wb.sheetnames == ["Software", "Summary", "Scan Status"]
        assert [c.value for c in wb["Software"][1]] == ["Computer", "Software", "Version", "Publisher", "Install Date", "Scope"]
        assert [c.value for c in wb["Scan Status"][1]] == ["Computer", "Result", "Apps Found", "Error"]


def test_export_with_rules_adds_policy_column_verdicts_and_a_violations_sheet(tmp_path):
    _, wb = export(tmp_path)
    assert wb.sheetnames == ["Software", "Summary", "Scan Status", "Policy Violations"]

    sw = wb["Software"]
    assert sw["G1"].value == "Policy"
    flagged = {(r[0].value, r[1].value): r[6].value for r in sw.iter_rows(min_row=2)}
    assert flagged[("PC-B", "AnyDesk 8")] == "Forbidden: AnyDesk"
    assert flagged[("PC-A", "Google Chrome")] in ("", None)
    row = next(r for r in sw.iter_rows(min_row=2) if r[1].value == "AnyDesk 8")
    assert row[1].fill.start_color.rgb[-6:] == "FFCDD2"

    verdicts = {r[0].value: r[4].value for r in wb["Scan Status"].iter_rows(min_row=2)}
    assert verdicts == {"PC-A": "Compliant", "PC-B": "Violation", "PC-C": "Violation", "PC-D": "Unknown"}


def test_violations_sheet_lists_each_breach(tmp_path):
    _, wb = export(tmp_path)
    rows = [tuple(c.value for c in r) for r in wb["Policy Violations"].iter_rows(min_row=2)]
    assert rows == [
        ("PC-B", "Forbidden software installed", "AnyDesk", "AnyDesk 8", "8.0.1"),
        ("PC-B", "Required software missing", "Sophos", None, None),
        ("PC-C", "Forbidden software installed", "uTorrent", "uTorrent", "3.5"),
    ]


def test_a_failed_machine_is_never_listed_as_missing_software(tmp_path):
    _, wb = export(tmp_path)
    assert "PC-D" not in {r[0].value for r in wb["Policy Violations"].iter_rows(min_row=2)}


def test_policy_text_cannot_inject_formulas_into_the_workbook(tmp_path):
    evil = '=HYPERLINK("http://evil.example","x")'
    path, wb = export(tmp_path, results=[result("PC-A", [app("Chrome")])], policy=Policy(required=[evil]))
    zf = zipfile.ZipFile(path)
    for member in zf.namelist():
        if member.startswith("xl/worksheets/sheet"):
            assert "<f>" not in zf.read(member).decode(), member
    assert wb["Policy Violations"]["C2"].value == evil


# --- GUI ------------------------------------------------------------------

def test_policy_dialog_round_trips_text(qapp):
    dialog = sww.PolicyDialog(Policy(forbidden=["AnyDesk"], required=["Sophos"]))
    assert dialog.forbidden_edit.toPlainText() == "AnyDesk"
    dialog.forbidden_edit.setPlainText("AnyDesk\n# note\n\nuTorrent\nanydesk")
    dialog.required_edit.setPlainText("Sophos")
    assert dialog.policy() == Policy(forbidden=["AnyDesk", "uTorrent"], required=["Sophos"])


def test_edit_policy_saves_on_ok_and_leaves_it_alone_on_cancel(monkeypatch, qapp):
    monkeypatch.setattr(sww.PolicyDialog, "exec_", lambda self: sww.QDialog.Accepted)
    sp.save_policy(Policy(forbidden=["Old"]))
    monkeypatch.setattr(sww.PolicyDialog, "policy", lambda self: Policy(forbidden=["New"], required=["Sophos"]))
    assert sww.edit_policy() == Policy(forbidden=["New"], required=["Sophos"])
    assert sp.load_policy().forbidden == ["New"]

    monkeypatch.setattr(sww.PolicyDialog, "exec_", lambda self: sww.QDialog.Rejected)
    monkeypatch.setattr(sww.PolicyDialog, "policy", lambda self: Policy(forbidden=["Ignored"]))
    assert sww.edit_policy() is None
    assert sp.load_policy().forbidden == ["New"]


def make_window(qapp):
    win = sww.SoftwareWindow(["PC-A", "PC-B", "PC-D"], None)
    for r in (RESULTS[0], RESULTS[1], RESULTS[3]):
        win.on_result(r)
    return win


def cells(win, col):
    return [win.table.item(r, col).text() for r in range(win.table.rowCount())]


def test_window_without_rules_shows_no_policy_noise(qapp):
    win = make_window(qapp)
    assert set(cells(win, sww._POLICY_COL)) == {""}
    assert "Violations" not in win.summary_label.text()
    win.close()


def test_window_flags_forbidden_and_missing_and_summarises(qapp):
    sp.save_policy(POLICY)
    win = make_window(qapp)
    by_software = dict(zip(cells(win, 1), cells(win, sww._POLICY_COL)))
    assert by_software["AnyDesk 8"] == "Forbidden: AnyDesk"
    assert by_software["(missing required: Sophos)"] == "Missing required"
    assert by_software["(scan failed)"] == "Unknown"
    text = win.summary_label.text()
    assert "Violations 1" in text and "Compliant 1" in text and "Unknown 1" in text
    colours = {win.table.item(r, 1).text(): win.table.item(r, 1).background().color() for r in range(win.table.rowCount())}
    assert colours["AnyDesk 8"] == sww._COLOR_FORBIDDEN
    assert colours["(missing required: Sophos)"] == sww._COLOR_MISSING
    win.close()


def test_editing_the_policy_redraws_existing_results_and_export_follows(monkeypatch, qapp, tmp_path):
    win = make_window(qapp)
    before = win.table.rowCount()
    monkeypatch.setattr(sww, "edit_policy", lambda parent=None: Policy(forbidden=["Chrome"]))
    win.on_edit_policy()
    assert "Forbidden: Chrome" in cells(win, sww._POLICY_COL)
    assert win.table.rowCount() == before                       # forbidden adds a flag, not rows
    assert "Violations 2" in win.summary_label.text()           # PC-A and PC-B both have Chrome

    out = tmp_path / "x.xlsx"
    win.export_to(str(out))
    assert "Policy Violations" in load_workbook(out).sheetnames

    monkeypatch.setattr(sww, "edit_policy", lambda parent=None: None)   # cancelled: nothing changes
    win.on_edit_policy()
    assert "Violations 2" in win.summary_label.text()
    win.close()


def test_filter_can_find_violations(qapp):
    sp.save_policy(POLICY)
    win = make_window(qapp)
    win.filter_edit.setText("forbidden")
    shown = [win.table.item(r, 1).text() for r in range(win.table.rowCount()) if not win.table.isRowHidden(r)]
    assert shown == ["AnyDesk 8"]
    win.close()


# --- import / export ------------------------------------------------------

import json  # noqa: E402


def write(tmp_path, content, name="p.json", mode="w", **kw):
    path = tmp_path / name
    with open(path, mode, **kw) as handle:
        handle.write(content)
    return str(path)


def test_export_then_import_round_trips_including_non_ascii(tmp_path):
    original = Policy(forbidden=["AnyDesk", "โปรแกรมต้องห้าม"], required=["Sophos"])
    path = str(tmp_path / "out.json")
    sp.export_policy(path, original)
    assert sp.import_policy(path) == original
    raw = open(path, encoding="utf-8").read()
    assert "โปรแกรมต้องห้าม" in raw and "\\u0" not in raw      # readable in Notepad, not \u escapes
    assert json.loads(raw)["version"] == 1


def test_import_accepts_a_windows_notepad_byte_order_mark(tmp_path):
    path = str(tmp_path / "bom.json")
    open(path, "wb").write(b"\xef\xbb\xbf" + '{"forbidden": ["AnyDesk"], "required": []}'.encode())
    assert sp.import_policy(path) == Policy(forbidden=["AnyDesk"])


def test_import_normalises_blanks_comments_and_duplicates(tmp_path):
    path = write(tmp_path, json.dumps({"forbidden": ["  AnyDesk ", "anydesk", "", "# note", "uTorrent"]}))
    assert sp.import_policy(path).forbidden == ["AnyDesk", "uTorrent"]


def test_one_list_alone_is_a_valid_policy(tmp_path):
    assert sp.import_policy(write(tmp_path, '{"required": ["Sophos"]}')) == Policy(required=["Sophos"])


@pytest.mark.parametrize("content, message", [
    ("not json at all", "not valid JSON"),
    ("[1, 2, 3]", "not a software policy"),
    ('"just a string"', "not a software policy"),
    # Regression guard: an unrelated JSON file (e.g. settings.json) must not
    # import as an empty policy and silently wipe the real one.
    ('{"stale_password_days": 45, "dhcp_server": ""}', "not a software policy"),
    ("{}", "not a software policy"),
    ('{"forbidden": "AnyDesk"}', "must be a list"),
    ('{"forbidden": ["ok", 5]}', "must be a list"),
    ('{"required": {"a": 1}}', "must be a list"),
])
def test_import_rejects_anything_that_is_not_a_policy(tmp_path, content, message):
    with pytest.raises(ValueError, match=message):
        sp.import_policy(write(tmp_path, content))


def test_import_rejects_bad_encoding_missing_and_oversized_files(tmp_path):
    binary = str(tmp_path / "b.json")
    open(binary, "wb").write(b"\xff\xfe\x00garbage")
    with pytest.raises(ValueError, match="not valid JSON"):
        sp.import_policy(binary)
    with pytest.raises(ValueError, match="Could not read"):
        sp.import_policy(str(tmp_path / "missing.json"))
    huge = write(tmp_path, '{"forbidden": ["' + "x" * (sp.MAX_IMPORT_BYTES + 10) + '"]}', name="huge.json")
    with pytest.raises(ValueError, match="too large"):
        sp.import_policy(huge)


def test_import_limits_the_number_of_rules(tmp_path):
    many = json.dumps({"forbidden": [f"app{i}" for i in range(sp.MAX_RULES_PER_LIST + 1)]})
    with pytest.raises(ValueError, match="limit is"):
        sp.import_policy(write(tmp_path, many))
    ok = json.dumps({"forbidden": [f"app{i}" for i in range(sp.MAX_RULES_PER_LIST)]})
    assert len(sp.import_policy(write(tmp_path, ok, name="ok.json")).forbidden) == sp.MAX_RULES_PER_LIST


def test_imported_rules_are_data_never_patterns(tmp_path):
    # A hostile file cannot smuggle in a regex: rules are escaped on use.
    policy = sp.import_policy(write(tmp_path, json.dumps({"forbidden": ["(a+)+$", ".*"]})))
    assert sp.matches(policy.forbidden[0], "aaaaaaaaaaaaaaaaaaaaaaaa!") is False
    assert sp.matches(policy.forbidden[1], "Google Chrome") is False


# --- the dialog's buttons -------------------------------------------------

def test_dialog_has_import_and_export_buttons_that_do_not_close_it(qapp, monkeypatch):
    dialog = sww.PolicyDialog(Policy())
    assert dialog.import_btn.text().startswith("Import") and dialog.export_btn.text().startswith("Export")
    monkeypatch.setattr(sww.QFileDialog, "getOpenFileName", staticmethod(lambda *a, **k: ("", "")))
    monkeypatch.setattr(sww.QFileDialog, "getSaveFileName", staticmethod(lambda *a, **k: ("", "")))
    dialog.show()
    for button in (dialog.import_btn, dialog.export_btn):
        button.click()
        assert dialog.isVisible(), "an action button must not accept/close the dialog"
    dialog.close()


def test_export_writes_what_is_on_screen_even_if_unsaved(qapp, tmp_path):
    sp.save_policy(Policy(forbidden=["Saved"]))
    dialog = sww.PolicyDialog(sp.load_policy())
    dialog.forbidden_edit.setPlainText("Typed but not saved\nuTorrent")
    path = str(tmp_path / "x.json")
    dialog.export_to(path)
    assert sp.import_policy(path).forbidden == ["Typed but not saved", "uTorrent"]
    assert sp.load_policy().forbidden == ["Saved"]            # exporting saves nothing


def test_import_into_empty_lists_does_not_ask(qapp, tmp_path, monkeypatch):
    dialog = sww.PolicyDialog(Policy())
    monkeypatch.setattr(dialog, "_ask_replace_or_merge", lambda: pytest.fail("asked on empty lists"))
    path = write(tmp_path, json.dumps({"forbidden": ["AnyDesk"], "required": ["Sophos"]}))
    assert dialog.import_from(path) == "replace"
    assert dialog.policy() == Policy(forbidden=["AnyDesk"], required=["Sophos"])


@pytest.mark.parametrize("choice, forbidden, required", [
    ("replace", ["AnyDesk", "utorrent"], ["Sophos"]),
    ("merge", ["uTorrent", "AnyDesk"], ["Defender", "Sophos"]),
])
def test_import_replace_or_merge(qapp, tmp_path, monkeypatch, choice, forbidden, required):
    dialog = sww.PolicyDialog(Policy(forbidden=["uTorrent"], required=["Defender"]))
    monkeypatch.setattr(dialog, "_ask_replace_or_merge", lambda: choice)
    path = write(tmp_path, json.dumps({"forbidden": ["AnyDesk", "utorrent"], "required": ["Sophos"]}))
    assert dialog.import_from(path) == choice
    got = dialog.policy()
    assert (got.forbidden, got.required) == (forbidden, required)     # merge also dedupes ignoring case
    # ... and the user sees a clean list in the editor, not duplicates that
    # only disappear once it is read back.
    assert dialog.forbidden_edit.toPlainText().splitlines() == forbidden
    assert dialog.required_edit.toPlainText().splitlines() == required


def test_cancelling_the_choice_leaves_the_lists_untouched(qapp, tmp_path, monkeypatch):
    dialog = sww.PolicyDialog(Policy(forbidden=["Keep"]))
    monkeypatch.setattr(dialog, "_ask_replace_or_merge", lambda: None)
    assert dialog.import_from(write(tmp_path, '{"forbidden": ["Other"]}')) is None
    assert dialog.policy().forbidden == ["Keep"]


def test_a_bad_file_warns_and_never_touches_the_lists(qapp, tmp_path, monkeypatch):
    dialog = sww.PolicyDialog(Policy(forbidden=["Keep"], required=["Keep2"]))
    shown = []
    monkeypatch.setattr(sww.QMessageBox, "warning", lambda *a: shown.append(a[2]))
    bad = write(tmp_path, '{"stale_password_days": 45}')
    monkeypatch.setattr(sww.QFileDialog, "getOpenFileName", staticmethod(lambda *a, **k: (bad, "")))
    dialog.on_import()
    assert shown and "not a software policy" in shown[0]
    assert dialog.policy() == Policy(forbidden=["Keep"], required=["Keep2"])


def test_import_only_loads_the_editors_nothing_is_saved_until_ok(qapp, tmp_path, monkeypatch):
    sp.save_policy(Policy(forbidden=["Saved"]))
    dialog = sww.PolicyDialog(sp.load_policy())
    monkeypatch.setattr(dialog, "_ask_replace_or_merge", lambda: "replace")
    dialog.import_from(write(tmp_path, '{"forbidden": ["Imported"]}'))
    assert dialog.policy().forbidden == ["Imported"]
    assert sp.load_policy().forbidden == ["Saved"]


def test_export_failure_is_reported_not_raised(qapp, tmp_path, monkeypatch):
    dialog = sww.PolicyDialog(Policy(forbidden=["A"]))
    errors = []
    monkeypatch.setattr(sww.QMessageBox, "critical", lambda *a: errors.append(a[2]))
    monkeypatch.setattr(sww.QFileDialog, "getSaveFileName",
                        staticmethod(lambda *a, **k: (str(tmp_path / "no" / "such" / "dir.json"), "")))
    dialog.on_export()
    assert errors
