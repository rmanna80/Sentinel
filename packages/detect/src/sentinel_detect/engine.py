"""The engine: feed it events, get back detections.

It owns the process tree, runs every rule against each event, and then does the two jobs that keep output
usable rather than overwhelming: it drops detections a suppression explains away, and it throttles repeats of
the same behaviour so one noisy condition does not become a thousand alerts. Everything is driven by the
event stream's own clock, so a replay of recorded events produces exactly the same detections every time —
which is what makes the whole thing testable and measurable.
"""

from __future__ import annotations

from collections.abc import Iterable
from datetime import datetime, timedelta

from sentinel_core.telemetry import Detection, TelemetryEvent

from .process_tree import ProcessTree
from .rules import Rule, default_rules
from .suppression import SuppressionList, default_suppressions


class Engine:
    def __init__(
        self,
        rules: list[Rule] | None = None,
        suppressions: SuppressionList | None = None,
        tree: ProcessTree | None = None,
        dedup_window: timedelta = timedelta(hours=1),
    ) -> None:
        self.tree = tree or ProcessTree()
        self.rules = rules if rules is not None else default_rules()
        self.suppressions = suppressions if suppressions is not None else default_suppressions()
        self.dedup_window = dedup_window
        self._last_emit: dict[str, datetime] = {}  # dedup_key -> last emitted detection time

    def feed(self, event: TelemetryEvent) -> list[Detection]:
        """Process one event in order and return the detections it surfaced (usually none)."""
        self.tree.ingest(event)
        raw: list[Detection] = []
        for rule in self.rules:
            rule.observe(event, self.tree, raw.append)

        surfaced: list[Detection] = []
        for detection in raw:
            if self.suppressions.suppresses(detection) is not None:
                continue
            if self._throttled(detection):
                continue
            self._last_emit[detection.dedup_key] = detection.last_ts
            surfaced.append(detection)
        return surfaced

    def feed_stream(self, events: Iterable[TelemetryEvent]) -> list[Detection]:
        """Replay a whole stream. Events are sorted by (time, sequence) so ordering is deterministic."""
        out: list[Detection] = []
        for event in sorted(events, key=lambda e: (e.ts, e.seq)):
            out.extend(self.feed(event))
        return out

    def _throttled(self, detection: Detection) -> bool:
        previous = self._last_emit.get(detection.dedup_key)
        if previous is None:
            return False
        return (detection.last_ts - previous) < self.dedup_window
