"""Non-secret application settings stored in the database, with typed defaults."""

from __future__ import annotations

from typing import Any

from sqlalchemy.orm import Session

from ..models import AppSetting

DEFAULTS: dict[str, Any] = {
    "notifications": {
        "min_severity": "high",  # notify for new findings and alerts at or above this
        "quiet_hours_enabled": False,
        "quiet_start": "22:00",
        "quiet_end": "07:00",
        "timezone": "America/New_York",
        "email_enabled": False,
        "email_to": "",
        "smtp_host": "",
        "smtp_port": 587,
        "smtp_username": "",
        "smtp_from": "",
        "smtp_starttls": True,
    },
    "integrations": {
        "osv": {"enabled": True},
        "nvd": {"enabled": True},
        "kev": {"enabled": True},
        "epss": {"enabled": True},
        "msrc": {"enabled": True},
        "hibp": {"enabled": False},
        "pwned_passwords": {"enabled": True},
        "ollama": {"enabled": False, "url": "http://127.0.0.1:11434", "model": "llama3.1:8b"},
    },
    "retention": {"log_event_days": 90, "metric_days": 90},
}


def get_setting(db: Session, key: str) -> Any:
    row = db.get(AppSetting, key)
    default = DEFAULTS.get(key)
    if row is None:
        return _copy(default)
    if isinstance(default, dict) and isinstance(row.value, dict):
        return _merge(default, row.value)
    return row.value


def set_setting(db: Session, key: str, value: Any) -> Any:
    row = db.get(AppSetting, key)
    if row is None:
        row = AppSetting(key=key, value=value)
        db.add(row)
    else:
        row.value = value
    db.flush()
    return get_setting(db, key)


def _copy(v: Any) -> Any:
    import copy

    return copy.deepcopy(v)


def _merge(default: dict[str, Any], value: dict[str, Any]) -> dict[str, Any]:
    out = _copy(default)
    for k, v in value.items():
        if isinstance(v, dict) and isinstance(out.get(k), dict):
            out[k] = _merge(out[k], v)
        else:
            out[k] = v
    return out


def integration_enabled(db: Session, name: str) -> bool:
    return bool(get_setting(db, "integrations").get(name, {}).get("enabled"))
