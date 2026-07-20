"""Stores per-run scan results so consecutive runs can be compared."""
import json
from datetime import datetime

from .config import app_data_dir

_MAX_RUNS = 30


def _runs_path():
    return app_data_dir() / "runs.json"


def load_runs() -> list[dict]:
    try:
        data = json.loads(_runs_path().read_text(encoding="utf-8"))
        return data if isinstance(data, list) else []
    except (OSError, ValueError):
        return []


def last_run() -> dict | None:
    """The most recent saved run: {"timestamp": ..., "statuses": {name: status}}."""
    runs = load_runs()
    return runs[-1] if runs else None


def save_run(statuses: dict[str, str]) -> None:
    runs = load_runs()
    runs.append({
        "timestamp": datetime.now().isoformat(timespec="seconds"),
        "statuses": statuses,
    })
    _runs_path().write_text(json.dumps(runs[-_MAX_RUNS:]), encoding="utf-8")
