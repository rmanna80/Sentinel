"""HTTP client for the Sentinel server. The agent always initiates; it never listens."""

from __future__ import annotations

import logging
import time
from typing import Any

import httpx
from sentinel_core.models import (
    AgentHello,
    AgentJob,
    CheckDescriptor,
    CheckRunResult,
    EnrollRequest,
    EnrollResponse,
    HeartbeatResponse,
    HostInfo,
    MetricSample,
    ScanCompletion,
    ScanPlan,
    ScanStatus,
)
from sentinel_core.telemetry import Detection

from . import __version__

log = logging.getLogger(__name__)


class AuthError(Exception):
    pass


class ServerClient:
    def __init__(self, server_url: str, token: str | None = None, timeout: float = 30.0,
                 transport: httpx.BaseTransport | None = None) -> None:
        headers = {"User-Agent": f"sentinel-agent/{__version__}"}
        if token:
            headers["Authorization"] = f"Bearer {token}"
        self._client = httpx.Client(base_url=server_url, timeout=timeout, headers=headers, transport=transport)

    def close(self) -> None:
        self._client.close()

    def _request(self, method: str, url: str, retries: int = 3, **kwargs: Any) -> httpx.Response:
        delay = 1.0
        for attempt in range(retries):
            try:
                resp = self._client.request(method, url, **kwargs)
            except httpx.TransportError as exc:
                if attempt == retries - 1:
                    raise
                log.warning("server unreachable (%s); retrying in %.0fs", exc, delay)
                time.sleep(delay)
                delay *= 2
                continue
            if resp.status_code == 401:
                raise AuthError("the server rejected this agent's token; enroll again")
            if resp.status_code >= 500 and attempt < retries - 1:
                time.sleep(delay)
                delay *= 2
                continue
            resp.raise_for_status()
            return resp
        raise RuntimeError("unreachable")  # pragma: no cover

    def enroll(self, code: str, host: HostInfo) -> EnrollResponse:
        body = EnrollRequest(code=code, host=host).model_dump(mode="json")
        return EnrollResponse.model_validate(self._request("POST", "/api/agent/enroll", json=body).json())

    def hello(self, host: HostInfo, checks: list[CheckDescriptor]) -> None:
        body = AgentHello(host=host, checks=checks).model_dump(mode="json")
        self._request("POST", "/api/agent/hello", json=body)

    def next_job(self, elevated: bool = False) -> AgentJob | None:
        resp = self._request("GET", "/api/agent/jobs/next", params={"elevated": "true" if elevated else "false"})
        if resp.status_code == 204 or not resp.content:
            return None
        return AgentJob.model_validate(resp.json())

    def send_metrics(self, samples: list[MetricSample]) -> None:
        self._request("POST", "/api/agent/metrics", json=[s.model_dump(mode="json") for s in samples], retries=1)

    def send_detections(self, detections: list[Detection]) -> None:
        if not detections:
            return
        body = [d.model_dump(mode="json") for d in detections]
        self._request("POST", "/api/agent/detections", json=body, retries=1)

    def complete(self, scan_id: int, status: ScanStatus, error: str | None = None) -> None:
        body = ScanCompletion(status=status, error=error).model_dump(mode="json")
        self._request("POST", f"/api/agent/scans/{scan_id}/complete", json=body)

    def scan_sink(self, scan_id: int) -> ScanSink:
        return ScanSink(self, scan_id)


class ScanSink:
    def __init__(self, client: ServerClient, scan_id: int) -> None:
        self._c = client
        self._id = scan_id

    def send_plan(self, plan: ScanPlan) -> None:
        self._c._request("POST", f"/api/agent/scans/{self._id}/plan", json=plan.model_dump(mode="json"))

    def send_result(self, result: CheckRunResult) -> None:
        self._c._request("POST", f"/api/agent/scans/{self._id}/results", json=result.model_dump(mode="json"))

    def heartbeat(self) -> bool:
        resp = self._c._request("POST", f"/api/agent/scans/{self._id}/heartbeat", retries=1)
        return HeartbeatResponse.model_validate(resp.json()).cancel
