"""API keys and other secrets: OS credential store first, private file as an honest fallback."""

from __future__ import annotations

import json
import logging
import os
from pathlib import Path

from ..config import get_settings

log = logging.getLogger(__name__)
SERVICE = "sentinel-server"


def _fallback_path() -> Path:
    return get_settings().data_dir / "secrets.json"


def _read_fallback() -> dict[str, str]:
    p = _fallback_path()
    if not p.exists():
        return {}
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}


def _write_fallback(data: dict[str, str]) -> None:
    p = _fallback_path()
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(data), encoding="utf-8")
    try:
        os.chmod(p, 0o600)
    except OSError:
        pass


def backend_name() -> str:
    try:
        import keyring

        kr = keyring.get_keyring()
        name = type(kr).__name__
        if "fail" in name.lower() or "null" in name.lower():
            return "file"
        return name
    except Exception:
        return "file"


def set_secret(name: str, value: str) -> str:
    if backend_name() != "file":
        try:
            import keyring

            keyring.set_password(SERVICE, name, value)
            data = _read_fallback()
            if data.pop(name, None) is not None:
                _write_fallback(data)
            return "credential store"
        except Exception as exc:
            log.warning("credential store write failed (%s); using private file", exc)
    data = _read_fallback()
    data[name] = value
    _write_fallback(data)
    return "private file"


def get_secret(name: str) -> str | None:
    if backend_name() != "file":
        try:
            import keyring

            v = keyring.get_password(SERVICE, name)
            if v:
                return v
        except Exception:  # noqa: S110
            pass
    return _read_fallback().get(name)


def delete_secret(name: str) -> None:
    if backend_name() != "file":
        try:
            import keyring

            keyring.delete_password(SERVICE, name)
        except Exception:  # noqa: S110
            pass
    data = _read_fallback()
    if data.pop(name, None) is not None:
        _write_fallback(data)


def has_secret(name: str) -> bool:
    return bool(get_secret(name))
