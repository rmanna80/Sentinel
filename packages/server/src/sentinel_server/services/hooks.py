"""Extension points so later phases can react to ingested data without editing the ingest path.

Each phase module registers its handlers at import time (see ``sentinel_server.phases``).
Handlers receive an open session and must not commit; the caller commits once.
A failing handler is logged and never breaks ingestion.
"""

from __future__ import annotations

import logging
from collections.abc import Callable
from typing import Any

log = logging.getLogger(__name__)

_handlers: dict[str, list[Callable[..., Any]]] = {
    "events_ingested": [],  # (db, device, scan, list[LogEventRecord])
    "software_ingested": [],  # (db, device, scan, check_run)
    "findings_created": [],  # (db, device, list[FindingRecord])
    "scan_completed": [],  # (db, scan)
}


def register(name: str, fn: Callable[..., Any]) -> None:
    if name not in _handlers:
        raise ValueError(f"unknown hook {name}")
    if fn not in _handlers[name]:
        _handlers[name].append(fn)


def fire(name: str, *args: Any) -> None:
    for fn in list(_handlers[name]):
        try:
            fn(*args)
        except Exception:
            log.exception("hook %s handler %s failed", name, getattr(fn, "__name__", fn))


def clear() -> None:
    for handlers in _handlers.values():
        handlers.clear()
