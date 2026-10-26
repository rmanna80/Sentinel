"""Server settings, read from SENTINEL_* environment variables or a .env file."""

from __future__ import annotations

import os
import sys
from enum import StrEnum
from functools import lru_cache
from pathlib import Path

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Mode(StrEnum):
    PRODUCTION = "production"  # fixture data is rejected
    DEMO = "demo"  # fixture data accepted and badged in the UI
    TEST = "test"


def default_data_dir() -> Path:
    if sys.platform == "win32":
        return Path(os.environ.get("LOCALAPPDATA", Path.home() / "AppData" / "Local")) / "Sentinel" / "server"
    return Path(os.environ.get("XDG_DATA_HOME", Path.home() / ".local" / "share")) / "sentinel-server"


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="SENTINEL_", env_file=".env", extra="ignore")

    mode: Mode = Mode.PRODUCTION
    host: str = "127.0.0.1"
    port: int = 8765
    data_dir: Path = Field(default_factory=default_data_dir)
    database_url: str | None = None
    web_dist: Path | None = None  # built dashboard; defaults to the packaged static folder

    session_idle_minutes: int = 30
    session_absolute_hours: int = 12
    login_attempts_per_minute: int = 5
    enrollment_code_minutes: int = 15
    agent_lease_seconds: int = 120
    scheduler_tick_seconds: int = 30
    scheduled_scan_grace_minutes: int = 30

    # Score shows "Incomplete" below this coverage.
    min_score_coverage: float = 0.75

    # Integrations stay off until configured in the UI.
    outbound_enabled: bool = True
    ollama_url: str = "http://127.0.0.1:11434"
    ollama_model: str = "llama3.1:8b"

    @property
    def db_url(self) -> str:
        if self.database_url:
            return self.database_url
        return f"sqlite:///{(self.data_dir / 'sentinel.db').as_posix()}"

    @property
    def allowed_hosts(self) -> set[str]:
        hosts = {f"127.0.0.1:{self.port}", f"localhost:{self.port}", f"[::1]:{self.port}"}
        if self.port == 80:
            hosts |= {"127.0.0.1", "localhost"}
        if self.mode is Mode.TEST:
            hosts.add("testserver")
        return hosts

    def static_dir(self) -> Path:
        if self.web_dist:
            return self.web_dist
        return Path(__file__).parent / "static"

    def ensure_dirs(self) -> None:
        for sub in ("", "reports", "logs"):
            (self.data_dir / sub).mkdir(parents=True, exist_ok=True)


@lru_cache
def get_settings() -> Settings:
    return Settings()
