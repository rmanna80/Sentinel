"""The measurement lab: score the detection engine instead of trusting it.

A detector you cannot measure is a detector you cannot improve or defend. This module turns the engine's
output into numbers against a corpus of *labelled* scenarios — streams tagged malicious or benign, with the
rules and ATT&CK techniques a malicious one should trigger. From that it computes the things that actually
tell you whether a detector is any good:

* **Recall** — of the malicious scenarios, how many did we catch?
* **Precision** — of everything we fired on, how much was real (i.e. did we stay quiet on benign activity)?
* **Technique coverage** — which ATT&CK techniques in the corpus do we detect?
* **Detection latency** — how long after a behaviour began did the detection fire? (Stream-clock time, so it
  is deterministic and comparable across runs.)
* **Throughput** — how many events per second the engine sustains, and its per-event cost.

The corpus in :mod:`.corpus` is small and hand-built — the same shape as Atomic Red Team's atomics, each a
documented scenario mapped to a technique. It is the yardstick you grow; a perfect score here means "correct
on the cases we have written down," never "correct in general," and the lab is honest about that distinction.
"""

from __future__ import annotations

import statistics
import time
from collections.abc import Callable
from dataclasses import dataclass, field

from sentinel_core.telemetry import EventKind, TelemetryEvent

from .engine import Engine

MALICIOUS = "malicious"
BENIGN = "benign"

EngineFactory = Callable[[], Engine]


@dataclass
class Scenario:
    """One labelled test case: a stream of events and what a correct engine should conclude about it."""

    name: str
    label: str  # MALICIOUS | BENIGN
    events: list[TelemetryEvent]
    expected_rules: frozenset[str] = frozenset()  # rule ids a malicious scenario should fire
    technique_ids: tuple[str, ...] = ()  # ATT&CK techniques this scenario exercises
    description: str = ""


@dataclass
class ScenarioResult:
    name: str
    label: str
    detected: bool
    fired_rules: set[str]
    missing_rules: set[str]  # expected but did not fire
    unexpected_rules: set[str]  # fired on a benign scenario — false positives
    latency_seconds: float | None  # for detected malicious scenarios


@dataclass
class Scorecard:
    results: list[ScenarioResult] = field(default_factory=list)
    tp: int = 0
    fp: int = 0
    fn: int = 0
    tn: int = 0
    technique_coverage: dict[str, bool] = field(default_factory=dict)

    @property
    def precision(self) -> float:
        return self.tp / (self.tp + self.fp) if (self.tp + self.fp) else 1.0

    @property
    def recall(self) -> float:
        return self.tp / (self.tp + self.fn) if (self.tp + self.fn) else 1.0

    @property
    def latencies(self) -> list[float]:
        return [r.latency_seconds for r in self.results if r.latency_seconds is not None]

    def latency_stats(self) -> dict[str, float]:
        lat = self.latencies
        if not lat:
            return {"count": 0}
        return {"count": len(lat), "min": min(lat), "median": statistics.median(lat), "max": max(lat)}

    def as_dict(self) -> dict[str, object]:
        covered = sum(1 for v in self.technique_coverage.values() if v)
        return {
            "counts": {"tp": self.tp, "fp": self.fp, "fn": self.fn, "tn": self.tn},
            "precision": round(self.precision, 4),
            "recall": round(self.recall, 4),
            "technique_coverage": {"covered": covered, "total": len(self.technique_coverage),
                                   "techniques": self.technique_coverage},
            "latency_seconds": self.latency_stats(),
            "scenarios": [
                {"name": r.name, "label": r.label, "detected": r.detected,
                 "fired": sorted(r.fired_rules), "missing": sorted(r.missing_rules),
                 "unexpected": sorted(r.unexpected_rules), "latency_seconds": r.latency_seconds}
                for r in self.results
            ],
        }


def score(scenarios: list[Scenario], engine_factory: EngineFactory = Engine) -> Scorecard:
    """Run each scenario through a fresh engine and tally the result. Scenarios never bleed into each other."""
    card = Scorecard()
    technique_hits: dict[str, bool] = {}
    for sc in scenarios:
        engine = engine_factory()  # fresh state per scenario
        detections = engine.feed_stream(sc.events)
        fired = {d.rule_id for d in detections}

        if sc.label == MALICIOUS:
            detected = sc.expected_rules <= fired if sc.expected_rules else bool(fired)
            missing = sc.expected_rules - fired
            latency = None
            if detected and detections and sc.events:
                first = min(e.ts for e in sc.events)
                fired_at = min(d.last_ts for d in detections)
                latency = max(0.0, (fired_at - first).total_seconds())
            card.results.append(ScenarioResult(sc.name, sc.label, detected, fired, missing, set(), latency))
            card.tp += int(detected)
            card.fn += int(not detected)
            for tech in sc.technique_ids:
                technique_hits[tech] = technique_hits.get(tech, False) or detected
        else:  # benign
            fp = bool(fired)
            card.results.append(ScenarioResult(sc.name, sc.label, False, fired, set(), set(fired), None))
            card.fp += int(fp)
            card.tn += int(not fp)

    card.technique_coverage = dict(sorted(technique_hits.items()))
    return card


# --------------------------------------------------------------------------- overhead


def measure_throughput(n_events: int = 5000, engine_factory: EngineFactory = Engine) -> dict[str, float]:
    """Feed a stream of benign events and report sustained throughput and per-event cost.

    Not a micro-benchmark — a rough, honest figure for "can this keep up with a busy host?" on this machine.
    """
    host = "BENCH"
    events: list[TelemetryEvent] = []
    for i in range(n_events):
        base = {"host": host, "seq": i, "pid": 1000 + (i % 500), "process_guid": f"g{i % 500}"}
        if i % 3 == 0:
            events.append(TelemetryEvent(kind=EventKind.PROCESS_CREATE, ts=_t(i), image=r"C:\Windows\System32\svchost.exe",
                                         parent_guid="g-root", parent_image=r"C:\Windows\System32\services.exe", **base))
        elif i % 3 == 1:
            events.append(TelemetryEvent(kind=EventKind.NETWORK_CONNECT, ts=_t(i), image=r"C:\app.exe",
                                         dest_ip="10.0.0.5", dest_port=443, direction="outbound", **base))
        else:
            events.append(TelemetryEvent(kind=EventKind.FILE_WRITE, ts=_t(i), image=r"C:\app.exe",
                                         file_path=r"C:\ProgramData\app\log.txt", **base))
    engine = engine_factory()
    start = time.perf_counter()
    for event in events:
        engine.feed(event)
    elapsed = time.perf_counter() - start
    eps = n_events / elapsed if elapsed > 0 else 0.0
    return {"events": float(n_events), "seconds": round(elapsed, 4),
            "events_per_second": round(eps, 1), "per_event_us": round(elapsed / n_events * 1e6, 2) if n_events else 0.0,
            "process_tree_size": float(len(engine.tree))}


def _t(seconds: int):
    from datetime import UTC, datetime, timedelta
    return datetime(2026, 1, 1, tzinfo=UTC) + timedelta(seconds=seconds)
