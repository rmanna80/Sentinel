"""Sentinel X: behavioural detection over operating-system telemetry.

An endpoint collector produces a stream of :class:`~sentinel_core.telemetry.TelemetryEvent`; the
:class:`~sentinel_detect.engine.Engine` correlates that stream with a process tree and a set of rules and
emits :class:`~sentinel_core.telemetry.Detection` objects — conclusions that carry their own evidence.
"""

from __future__ import annotations

from sentinel_core.telemetry import Detection, EventKind, ProcessSnapshot, TelemetryEvent

from . import attack
from .engine import Engine
from .process_tree import ProcessNode, ProcessTree
from .replay import StreamBuilder, dump_stream, load_stream, run_replay
from .rules import Rule, default_rules
from .suppression import Suppression, SuppressionList, default_suppressions

__all__ = [
    "Detection",
    "Engine",
    "EventKind",
    "ProcessNode",
    "ProcessSnapshot",
    "ProcessTree",
    "Rule",
    "StreamBuilder",
    "Suppression",
    "SuppressionList",
    "TelemetryEvent",
    "attack",
    "default_rules",
    "default_suppressions",
    "dump_stream",
    "load_stream",
    "run_replay",
]
