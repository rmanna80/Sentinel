"""Shared fixtures: an isolated server, a signed-in browser client, and an enrolled fixture agent."""

from __future__ import annotations

from collections.abc import Callable, Iterator
from typing import Any

import httpx
import pytest
from fastapi.testclient import TestClient
from sentinel_agent.registry import CheckRegistry
from sentinel_agent.runner import ScanRunner
from sentinel_agent.testing import FixtureContext, windows_host
from sentinel_agent.transport import ServerClient
from sentinel_core.models import DataMode, HostInfo, ScanStatus
from sentinel_server.config import Mode, Settings, get_settings
from sentinel_server.security import rate_limiter

PASSWORD = "correct-horse-battery-9"


@pytest.fixture
def settings(tmp_path, monkeypatch) -> Settings:
    monkeypatch.setenv("SENTINEL_MODE", "test")
    monkeypatch.setenv("SENTINEL_DATA_DIR", str(tmp_path / "data"))
    monkeypatch.setenv("SENTINEL_WEB_DIST", str(tmp_path / "no-web"))
    get_settings.cache_clear()
    rate_limiter.reset()
    s = get_settings()
    yield s
    get_settings.cache_clear()


@pytest.fixture
def app(settings):
    from sentinel_server.app import create_app

    return create_app(settings, start_background=False, run_migrations=False)


@pytest.fixture
def anon(app) -> Iterator[TestClient]:
    with TestClient(app) as client:
        yield client


class Browser:
    """A signed-in dashboard session that sends the CSRF header like the web app does."""

    def __init__(self, client: TestClient, csrf: str) -> None:
        self.client = client
        self.csrf = csrf

    def get(self, url: str, **kw: Any) -> httpx.Response:
        return self.client.get(url, **kw)

    def post(self, url: str, **kw: Any) -> httpx.Response:
        return self.client.post(url, headers={"X-CSRF-Token": self.csrf}, **kw)

    def patch(self, url: str, **kw: Any) -> httpx.Response:
        return self.client.patch(url, headers={"X-CSRF-Token": self.csrf}, **kw)

    def put(self, url: str, **kw: Any) -> httpx.Response:
        return self.client.put(url, headers={"X-CSRF-Token": self.csrf}, **kw)

    def delete(self, url: str, **kw: Any) -> httpx.Response:
        return self.client.delete(url, headers={"X-CSRF-Token": self.csrf}, **kw)


@pytest.fixture
def browser(app, anon) -> Browser:
    token = app.state.setup_token
    r = anon.post("/api/auth/setup", json={"setup_token": token, "username": "ryan", "password": PASSWORD})
    assert r.status_code == 200, r.text
    return Browser(anon, r.json()["csrf_token"])


class FixtureAgent:
    """The real agent runner and transport, answering jobs from in-memory fixtures."""

    def __init__(self, app, browser: Browser, checks: list[type], host: HostInfo | None = None) -> None:
        self.browser = browser
        self.host = host or windows_host()
        self.registry = CheckRegistry(checks)
        code = browser.post("/api/devices/enrollment-codes").json()["code"]
        transport = browser.client._transport  # type: ignore[attr-defined]
        enrollment = ServerClient("http://testserver", transport=transport).enroll(code, self.host)
        self.device_id = enrollment.device_id
        self.client = ServerClient("http://testserver", enrollment.device_token, transport=transport)
        self.client.hello(self.host, self.registry.descriptors())

    def run_next(self, fixture: dict[str, Any], *, elevated: bool = False,
                 data_mode: DataMode | None = None) -> ScanStatus | None:
        job = self.client.next_job(elevated=elevated)
        if job is None:
            return None
        if data_mode is not None:
            job = job.model_copy(update={"data_mode": data_mode})
        host = self.host

        def factory(check, params, cancelled):
            return FixtureContext(host, fixture, params=params, cancelled=cancelled)

        sink = self.client.scan_sink(job.scan_id)
        status = ScanRunner(self.registry, host, factory, sink, poll_interval=0.01).run(job)
        self.client.complete(job.scan_id, status)
        return status

    def scan(self, fixture: dict[str, Any], scan_type: str = "posture", **kw: Any) -> dict[str, Any]:
        r = self.browser.post("/api/scans", json={"device_id": self.device_id, "scan_type": scan_type, **kw})
        assert r.status_code == 201, r.text
        scan_id = r.json()["id"]
        self.run_next(fixture, elevated=kw.get("elevated", False))
        return self.browser.get(f"/api/scans/{scan_id}").json()


@pytest.fixture
def make_agent(app, browser) -> Callable[..., FixtureAgent]:
    def make(checks: list[type], host: HostInfo | None = None) -> FixtureAgent:
        return FixtureAgent(app, browser, checks, host)

    return make


@pytest.fixture
def production(monkeypatch, settings):
    monkeypatch.setattr(settings, "mode", Mode.PRODUCTION)
    return settings
