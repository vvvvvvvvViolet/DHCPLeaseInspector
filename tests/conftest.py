import os
import time
from datetime import datetime, timedelta, timezone

import pytest

# Must be set before Qt is imported anywhere: no display in CI.
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")


@pytest.fixture(autouse=True)
def isolated_appdata(tmp_path, monkeypatch):
    """Every test gets its own settings/history dir and default settings."""
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path / "appdata"))
    from dhcp_inspector import config

    monkeypatch.setattr(config, "_settings", None)


@pytest.fixture(scope="session")
def qapp():
    from PyQt5.QtWidgets import QApplication

    return QApplication.instance() or QApplication([])


def days_ago(days: float) -> str:
    return (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()


def dotnet_days_ago(days: float) -> str:
    """A timestamp as PowerShell's ToString("o") writes it: 7 fraction digits."""
    stamp = datetime.now(timezone.utc) - timedelta(days=days)
    return stamp.strftime("%Y-%m-%dT%H:%M:%S.") + f"{stamp.microsecond:06d}1+00:00"


def wait_for(app, predicate, timeout=20.0):
    deadline = time.time() + timeout
    while time.time() < deadline:
        app.processEvents()
        if predicate():
            app.processEvents()
            return
        time.sleep(0.01)
    raise AssertionError("timed out waiting for condition")


def run_scan(app, window, start):
    """Kick off a scan via `start()` and block until its worker finishes."""
    start()
    wait_for(app, lambda: window._worker is None or not window._worker.isRunning())
