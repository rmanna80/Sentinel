"""Phase modules plug in here without editing the app factory.

Each module in ``PHASE_MODULES`` may expose:

* ``router``: a FastAPI ``APIRouter`` (user routes must depend on ``current_auth``)
* ``register_hooks()``: attach handlers with ``services.hooks.register``
* ``tick(db)``: called by the background loop every ``scheduler_tick_seconds``; must not commit

A module that is missing is skipped with a log line, so the core runs on its own.
"""

from __future__ import annotations

import importlib
import logging
from types import ModuleType

log = logging.getLogger(__name__)

PHASE_MODULES = [
    "detection",  # Phase 2: log-based detection rules, alerts, incidents, IOC hashes
    "schedules",  # Phase 2: scheduled scans and missed-run alerts
    "notifications",  # Phase 2/6: notifications with dedupe, thresholds, quiet hours, email
    "logs",  # Phase 2: log event search and statistics
    "vulns",  # Phase 3: software inventory, OSV/NVD/MSRC/KEV/EPSS matching
    "email_security",  # Phase 4: HIBP and Pwned Passwords
    "network",  # Phase 5: scope controls and network scans
    "assistant",  # Phase 6: evidence-grounded AI assistant
    "analytics",  # Phase 6: analytics endpoints
    "reports",  # Phase 6: PDF / CSV / JSON reports
]


def load() -> list[ModuleType]:
    loaded = []
    for name in PHASE_MODULES:
        try:
            module = importlib.import_module(f"{__name__}.{name}")
        except ModuleNotFoundError as exc:
            if exc.name == f"{__name__}.{name}":
                log.info("phase module %s not present; skipping", name)
                continue
            raise
        loaded.append(module)
    return loaded
