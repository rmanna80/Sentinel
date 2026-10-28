"""One telemetry cycle: collect new events, correlate them, ship any detections.

Kept as a tiny pure function so the agent's run loop stays simple and this logic is testable with a stub
collector and a stub client. The engine is long-lived (it holds the process tree and in-flight rule state
across cycles); the collector and client are passed in each cycle.
"""

from __future__ import annotations

from typing import Protocol

from sentinel_core.telemetry import Detection
from sentinel_detect import Engine

from .collector import Collector


class _Shipper(Protocol):
    def send_detections(self, detections: list[Detection]) -> None: ...


def run_cycle(collector: Collector, engine: Engine, client: _Shipper) -> list[Detection]:
    """Collect the events available now, feed them to the persistent engine, ship any detections."""
    events = collector.collect()
    detections = engine.feed_stream(events)
    if detections:
        client.send_detections(detections)
    return detections
