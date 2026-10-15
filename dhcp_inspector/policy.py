"""Software policy: titles that must not be installed, and titles that must be.

The lists are edited by the user in the app and saved next to the settings
file, so no code change is needed to add or remove an entry.

A rule is matched against the software name, ignoring case. It is a
substring match ("teamviewer" matches "TeamViewer 15 Host"), and "*" stands
for any run of characters ("anydesk*", "microsoft * 2019"). Every other
character, brackets and parentheses included, is taken literally, so an
entry like "Visual C++ 2015 (x64)" means what it says.
"""
import json
import re
from dataclasses import dataclass, field

from .config import app_data_dir


@dataclass
class Policy:
    forbidden: list[str] = field(default_factory=list)
    required: list[str] = field(default_factory=list)

    @property
    def empty(self) -> bool:
        return not self.forbidden and not self.required


def parse_rules(text: str) -> list[str]:
    """Turn editor text into rules: one per line, blanks and #comments dropped,
    duplicates (ignoring case) removed, original order kept."""
    rules, seen = [], set()
    for line in (text or "").splitlines():
        rule = line.strip()
        if not rule or rule.startswith("#"):
            continue
        if rule.casefold() in seen:
            continue
        seen.add(rule.casefold())
        rules.append(rule)
    return rules


def _compile(rule: str):
    parts = [re.escape(piece) for piece in rule.casefold().split("*")]
    return re.compile(".*".join(parts))


def matches(rule: str, name: str) -> bool:
    return _compile(rule).search((name or "").casefold()) is not None


# --- storage --------------------------------------------------------------

def _policy_path():
    return app_data_dir() / "software_policy.json"


def load_policy() -> Policy:
    try:
        data = json.loads(_policy_path().read_text(encoding="utf-8"))
        return Policy(
            forbidden=parse_rules("\n".join(str(r) for r in data.get("forbidden", []))),
            required=parse_rules("\n".join(str(r) for r in data.get("required", []))),
        )
    except (OSError, ValueError, AttributeError):
        return Policy()  # missing or corrupt file -> no rules


def _to_json(policy: Policy) -> str:
    return json.dumps(
        {"version": 1, "forbidden": policy.forbidden, "required": policy.required},
        indent=2, ensure_ascii=False,
    )


def save_policy(policy: Policy) -> None:
    _policy_path().write_text(_to_json(policy), encoding="utf-8")


# --- import / export ------------------------------------------------------

# A policy is a short list of titles; anything bigger is the wrong file.
MAX_IMPORT_BYTES = 1_000_000
MAX_RULES_PER_LIST = 1000


def export_policy(path: str, policy: Policy) -> None:
    with open(path, "w", encoding="utf-8") as handle:
        handle.write(_to_json(policy))


def import_policy(path: str) -> Policy:
    """Read a policy file written by export_policy.

    Raises ValueError, with a message fit to show the user, for anything
    that is not a policy. Strictness is deliberate: importing a stray
    settings.json as an empty policy would silently wipe the real one.
    """
    try:
        with open(path, "rb") as handle:
            raw = handle.read(MAX_IMPORT_BYTES + 1)
    except OSError as exc:
        raise ValueError(f"Could not read the file: {exc}") from exc
    if len(raw) > MAX_IMPORT_BYTES:
        raise ValueError("That file is too large to be a software policy.")

    try:
        # utf-8-sig: Notepad on Windows writes a byte-order mark.
        data = json.loads(raw.decode("utf-8-sig"))
    except (UnicodeDecodeError, ValueError):
        raise ValueError("That file is not valid JSON, so it is not a software policy.") from None

    if not isinstance(data, dict) or not ({"forbidden", "required"} & data.keys()):
        raise ValueError(
            'That file is not a software policy: it has no "forbidden" or "required" list.'
        )

    lists = {}
    for key in ("forbidden", "required"):
        value = data.get(key, [])
        if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
            raise ValueError(f'"{key}" must be a list of text entries.')
        rules = parse_rules("\n".join(value))
        if len(rules) > MAX_RULES_PER_LIST:
            raise ValueError(f'"{key}" has {len(rules)} entries; the limit is {MAX_RULES_PER_LIST}.')
        lists[key] = rules
    return Policy(forbidden=lists["forbidden"], required=lists["required"])


# --- evaluation -----------------------------------------------------------

COMPLIANT = "Compliant"
VIOLATION = "Violation"
UNKNOWN = "Unknown"


def evaluate(result: dict, policy: Policy) -> dict:
    """Judge one computer's inventory result against the policy.

    Returns {"status", "forbidden": [(rule, app)], "missing": [rule]}.

    A forbidden title that was seen is a violation even in a partial list.
    "Missing" can only be claimed from a complete list: after a failed or
    interrupted read we don't know what is installed, so that machine is
    Unknown rather than wrongly reported as lacking its antivirus.
    """
    found = []
    if result.get("ok"):
        for rule in policy.forbidden:
            pattern = _compile(rule)
            for app in result.get("apps", []):
                if pattern.search(app["name"].casefold()):
                    found.append((rule, app))

    complete = bool(result.get("ok")) and not result.get("partial")
    missing = []
    if complete:
        for rule in policy.required:
            pattern = _compile(rule)
            if not any(pattern.search(app["name"].casefold()) for app in result.get("apps", [])):
                missing.append(rule)

    if found or missing:
        status = VIOLATION
    elif not complete and not policy.empty:
        status = UNKNOWN
    else:
        status = COMPLIANT
    return {"status": status, "forbidden": found, "missing": missing}
