"""User-tunable settings, persisted to the per-user app data directory."""
import json
import os
from dataclasses import asdict, dataclass, fields
from pathlib import Path


@dataclass
class Settings:
    stale_password_days: int = 45   # computer-account password age -> "(Stale)"
    max_parallel_ping: int = 60     # phase-1 DNS/ping sweep concurrency
    max_parallel_wmi: int = 15      # phase-2 WMI concurrency
    ping_timeout_ms: int = 2000
    wmi_timeout_s: int = 60         # whole-PowerShell budget per machine
    wmi_only_ping_ok: bool = True   # skip WMI for machines that failed ping


def app_data_dir() -> Path:
    base = os.environ.get("LOCALAPPDATA")
    root = Path(base) if base else Path.home()
    directory = root / "DHCPLeaseInspector"
    directory.mkdir(parents=True, exist_ok=True)
    return directory


def _settings_path() -> Path:
    return app_data_dir() / "settings.json"


def load_settings() -> Settings:
    settings = Settings()
    try:
        data = json.loads(_settings_path().read_text(encoding="utf-8"))
        for field in fields(Settings):
            if field.name in data:
                setattr(settings, field.name, data[field.name])
    except (OSError, ValueError):
        pass  # missing or corrupt file -> defaults
    return settings


_settings: Settings | None = None


def get_settings() -> Settings:
    global _settings
    if _settings is None:
        _settings = load_settings()
    return _settings


def save_settings(settings: Settings) -> None:
    global _settings
    _settings = settings
    _settings_path().write_text(json.dumps(asdict(settings), indent=2), encoding="utf-8")
