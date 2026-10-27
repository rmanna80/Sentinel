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
    # Local-first: nothing the server does on its own reaches the internet until you turn it on.
    # Pwned Passwords stays on because it only runs when you type a password into its check yourself,
    # and only a 5-character hash prefix is sent.
    "integrations": {
        "osv": {"enabled": False},
        "nvd": {"enabled": False},
        "kev": {"enabled": False},
        "epss": {"enabled": False},
        "msrc": {"enabled": False},
        "hibp": {"enabled": False},
        "pwned_passwords": {"enabled": True},
        # Threat-intelligence feed. Fetches public Hacker News search results (no account, nothing about you
        # is sent) and matches headlines to your inventory. Off by default like every outbound integration.
        "hackernews": {"enabled": False, "min_points": 20, "refresh_hours": 6},
        "ollama": {"enabled": False, "url": "http://127.0.0.1:11434", "model": "llama3.1:8b"},
    },
    # Networks you own, so an uploaded Wi-Fi survey can flag an evil-twin AP imitating your SSID,
    # or an open/WEP network that is actually yours. Everything else is left classified "unknown".
    "field_data": {"own_ssids": [], "own_bssids": []},
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
