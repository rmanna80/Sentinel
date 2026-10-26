"""Agent configuration, local state and device-token storage."""

from __future__ import annotations

import contextlib
import json
import logging
import os
import sys
import threading
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

log = logging.getLogger(__name__)

KEYRING_SERVICE = "sentinel-agent"


def agent_home() -> Path:
    override = os.environ.get("SENTINEL_AGENT_HOME")
    if override:
        base = Path(override)
    elif sys.platform == "win32":
        base = Path(os.environ.get("LOCALAPPDATA", Path.home() / "AppData" / "Local")) / "Sentinel" / "agent"
    else:
        base = Path(os.environ.get("XDG_CONFIG_HOME", Path.home() / ".config")) / "sentinel-agent"
    base.mkdir(parents=True, exist_ok=True)
    return base


@dataclass
class AgentConfig:
    server_url: str | None = None
    device_id: int | None = None
    poll_interval_seconds: float = 5.0
    metrics_interval_seconds: float = 60.0
    # Folders the malware check may scan. Nothing outside these is ever scanned.
    malware_scan_paths: list[str] = field(default_factory=list)
    # Development projects whose dependency manifests are checked for known vulnerabilities.
    project_paths: list[str] = field(default_factory=list)

    @classmethod
    def load(cls) -> AgentConfig:
        path = agent_home() / "agent.json"
        if not path.exists():
            return cls()
        data = json.loads(path.read_text(encoding="utf-8"))
        known = {k: v for k, v in data.items() if k in cls.__dataclass_fields__}
        return cls(**known)

    def save(self) -> None:
        path = agent_home() / "agent.json"
        path.write_text(json.dumps(asdict(self), indent=2), encoding="utf-8")

    def as_mapping(self) -> dict[str, Any]:
        return asdict(self)


def validate_server_url(url: str) -> str:
    """Plain HTTP is only allowed to this machine; anything remote must use HTTPS."""
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        raise ValueError("server URL must look like http://127.0.0.1:8765")
    if parsed.scheme == "http" and parsed.hostname not in ("127.0.0.1", "localhost", "::1"):
        raise ValueError("plain HTTP is only allowed to 127.0.0.1; use HTTPS for a remote server")
    return url.rstrip("/")


# --------------------------------------------------------------------------- device token


def _token_file() -> Path:
    return agent_home() / "device_token"


def store_token(server_url: str, token: str) -> str:
    """Store the device token in the OS credential store; fall back to a private file."""
    try:
        import keyring

        keyring.set_password(KEYRING_SERVICE, server_url, token)
        with contextlib.suppress(FileNotFoundError):
            _token_file().unlink()
        return "credential store"
    except Exception as exc:  # keyring backends vary; headless Linux often has none
        log.warning("credential store unavailable (%s); using a private file", exc)
        path = _token_file()
        path.write_text(token, encoding="utf-8")
        with contextlib.suppress(OSError):
            os.chmod(path, 0o600)
        return str(path)


def load_token(server_url: str) -> str | None:
    try:
        import keyring

        token = keyring.get_password(KEYRING_SERVICE, server_url)
        if token:
            return token
    except Exception:  # noqa: S110 - fall through to the file fallback
        pass
    path = _token_file()
    if path.exists():
        return path.read_text(encoding="utf-8").strip() or None
    return None


# --------------------------------------------------------------------------- local state


class FileState:
    """Persistent key/value store for things like log cursors."""

    def __init__(self, path: Path | None = None) -> None:
        self._path = path or (agent_home() / "state.json")
        self._lock = threading.Lock()
        self._data: dict[str, str] = {}
        if self._path.exists():
            try:
                self._data = json.loads(self._path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                log.warning("agent state file unreadable; starting fresh")

    def get(self, key: str, default: str | None = None) -> str | None:
        with self._lock:
            return self._data.get(key, default)

    def set(self, key: str, value: str) -> None:
        with self._lock:
            self._data[key] = value
            tmp = self._path.with_suffix(".tmp")
            tmp.write_text(json.dumps(self._data, indent=2), encoding="utf-8")
            tmp.replace(self._path)


class MemoryState:
    def __init__(self, data: dict[str, str] | None = None) -> None:
        self._data = dict(data or {})

    def get(self, key: str, default: str | None = None) -> str | None:
        return self._data.get(key, default)

    def set(self, key: str, value: str) -> None:
        self._data[key] = value
