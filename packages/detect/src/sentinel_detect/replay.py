"""Replay: run recorded or synthetic event streams through the engine.

This is where the "fixture-first" philosophy of the rest of Sentinel meets the detection engine. We cannot
run Event Tracing for Windows in a test (or on Linux CI), so instead the engine is exercised against streams
of events — built in code with :class:`StreamBuilder`, or loaded from a ``.jsonl`` recording. The same path
powers three things: the unit tests, the ``sentinel-detect`` command for trying a stream by hand, and, later,
the measurement lab that scores detections against documented test cases.

A stream file is JSON Lines: one :class:`TelemetryEvent` object per line. Blank lines and lines beginning
with ``#`` or ``//`` are ignored, so a recording can carry comments.
"""

from __future__ import annotations

import argparse
import itertools
import json
import sys
from collections.abc import Iterable
from datetime import UTC, datetime, timedelta
from pathlib import Path

from sentinel_core.telemetry import Detection, EventKind, TelemetryEvent

from .engine import Engine

# --------------------------------------------------------------------------- building streams


class StreamBuilder:
    """Builds an ordered event stream with sensible defaults, auto-incrementing sequence and clock.

    Each call advances the clock by ``step`` (overridable per event with ``ts``) and assigns the next
    sequence number, so a test reads like a timeline instead of a pile of timestamps.
    """

    def __init__(self, host: str = "TEST-PC", start: datetime | None = None,
                 step: timedelta = timedelta(seconds=1)) -> None:
        self.host = host
        self.step = step
        self.events: list[TelemetryEvent] = []
        self._ts = start or datetime(2026, 1, 1, 12, 0, 0, tzinfo=UTC)
        self._seq = itertools.count()
        self._pid = itertools.count(1000)

    def _emit(self, ts: datetime | None, **fields: object) -> TelemetryEvent:
        when = ts or self._ts
        self._ts = when + self.step
        event = TelemetryEvent(host=self.host, ts=when, seq=next(self._seq), **fields)  # type: ignore[arg-type]
        self.events.append(event)
        return event

    def process_create(self, process_guid: str, image: str, *, parent_guid: str | None = None,
                        parent_image: str | None = None, command_line: str | None = None,
                        user: str | None = None, pid: int | None = None, parent_pid: int | None = None,
                        ts: datetime | None = None) -> TelemetryEvent:
        return self._emit(ts, kind=EventKind.PROCESS_CREATE, process_guid=process_guid, image=image,
                          pid=pid if pid is not None else next(self._pid), parent_guid=parent_guid,
                          parent_image=parent_image, command_line=command_line, user=user, parent_pid=parent_pid)

    def process_exit(self, process_guid: str, *, pid: int = 0, exit_code: int = 0,
                     ts: datetime | None = None) -> TelemetryEvent:
        return self._emit(ts, kind=EventKind.PROCESS_EXIT, process_guid=process_guid, pid=pid, exit_code=exit_code)

    def network_connect(self, process_guid: str, dest_ip: str, dest_port: int, *, image: str = "",
                        protocol: str = "tcp", direction: str = "outbound", pid: int = 0,
                        ts: datetime | None = None) -> TelemetryEvent:
        return self._emit(ts, kind=EventKind.NETWORK_CONNECT, process_guid=process_guid, image=image, pid=pid,
                          dest_ip=dest_ip, dest_port=dest_port, protocol=protocol, direction=direction)

    def registry_set(self, process_guid: str, registry_path: str, registry_value: str, *,
                     value: object = None, image: str = "", pid: int = 0,
                     ts: datetime | None = None) -> TelemetryEvent:
        details = {} if value is None else {"value": value}
        return self._emit(ts, kind=EventKind.REGISTRY_SET, process_guid=process_guid, image=image, pid=pid,
                          registry_path=registry_path, registry_value=registry_value, details=details)

    def file_write(self, process_guid: str, file_path: str, *, image: str = "", pid: int = 0,
                   ts: datetime | None = None) -> TelemetryEvent:
        return self._emit(ts, kind=EventKind.FILE_WRITE, process_guid=process_guid, image=image, pid=pid,
                          file_path=file_path)


# --------------------------------------------------------------------------- loading / running


def load_stream(path: str | Path) -> list[TelemetryEvent]:
    events: list[TelemetryEvent] = []
    for line in Path(path).read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith(("#", "//")):
            continue
        events.append(TelemetryEvent(**json.loads(stripped)))
    return events


def run_replay(events: Iterable[TelemetryEvent], engine: Engine | None = None) -> list[Detection]:
    return (engine or Engine()).feed_stream(events)


def dump_stream(events: Iterable[TelemetryEvent]) -> str:
    """Serialise events back to JSON Lines (how the sample recordings are produced)."""
    return "\n".join(e.model_dump_json(exclude_defaults=True) for e in events) + "\n"


# --------------------------------------------------------------------------- CLI


def _format(detection: Detection) -> str:
    techniques = ", ".join(f"{i} ({n})" for i, n in zip(detection.technique_ids, detection.technique_names,
                                                         strict=False))
    lines = [
        f"[{detection.severity.upper()}] {detection.title}",
        f"  rule: {detection.rule_id}   confidence: {detection.confidence}   host: {detection.host}",
        f"  when: {detection.first_ts.isoformat()} -> {detection.last_ts.isoformat()}",
    ]
    if techniques:
        lines.append(f"  ATT&CK: {techniques}")
    lines += [f"  {detection.summary}", "", "  " + detection.explanation.replace("\n", "\n  ")]
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="sentinel-detect",
        description="Replay a telemetry event stream (JSON Lines) through the Sentinel X detection engine.",
    )
    parser.add_argument("stream", type=Path, help="path to a .jsonl event stream")
    parser.add_argument("--json", action="store_true", help="emit detections as JSON instead of text")
    parser.add_argument("--no-suppress", action="store_true", help="ignore the default suppression list")
    args = parser.parse_args(argv)

    from .suppression import SuppressionList

    events = load_stream(args.stream)
    engine = Engine(suppressions=SuppressionList([]) if args.no_suppress else None)
    detections = engine.feed_stream(events)

    if args.json:
        print(json.dumps([d.model_dump(mode="json") for d in detections], indent=2))
    else:
        print(f"Replayed {len(events)} events; {len(detections)} detection(s).\n")
        for detection in detections:
            print(_format(detection))
            print("-" * 78)
    return 0


if __name__ == "__main__":
    sys.exit(main())
