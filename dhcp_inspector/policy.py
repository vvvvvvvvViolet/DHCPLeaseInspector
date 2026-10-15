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


def save_policy(policy: Policy) -> None:
    _policy_path().write_text(
        json.dumps({"forbidden": policy.forbidden, "required": policy.required},
                   indent=2, ensure_ascii=False),
        encoding="utf-8",
    )


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
