"""Load recorded telemetry from disk, whatever shape it was saved in.

Three formats cover what you will meet in practice:

* ``.jsonl`` - Sentinel X's own stream format (one :class:`TelemetryEvent` per line);
* ``.xml`` - a Sysmon log exported from a Windows machine with ``wevtutil qe`` or ``Get-WinEvent``;
* ``.json`` - EVTX converted to JSON, which is how public attack datasets are usually published.

Binary ``.evtx`` files are not read directly; convert them first (``evtx_dump --format json`` from the
`evtx <https://github.com/omerbenamram/evtx>`_ project, or ``wevtutil qe file.evtx /lf:true /f:xml``).
"""

from __future__ import annotations

from pathlib import Path

from sentinel_core.telemetry import TelemetryEvent

from .sysmon import parse_evtx_json, parse_sysmon_log

SUFFIXES = (".jsonl", ".xml", ".json")


def load_recording(path: str | Path) -> list[TelemetryEvent]:
    """Events from one recorded file. Raises ``ValueError`` for a format that cannot be read."""
    file = Path(path)
    suffix = file.suffix.lower()
    if suffix == ".evtx":
        raise ValueError("binary .evtx is not read directly; convert it to JSON or XML first")
    if suffix not in SUFFIXES:
        raise ValueError(f"unrecognised recording type '{suffix}'")
    text = file.read_text(encoding="utf-8-sig", errors="replace")
    if suffix == ".xml":
        return parse_sysmon_log(text)
    if suffix == ".json":
        return parse_evtx_json(text)
    from sentinel_detect.replay import load_stream

    return load_stream(file)


def find_recordings(paths: list[str | Path]) -> list[Path]:
    """Every readable recording under ``paths`` (files are taken as given; folders are searched)."""
    found: list[Path] = []
    for root in map(Path, paths):
        if root.is_file():
            found.append(root)
        elif root.is_dir():
            found.extend(sorted(p for p in root.rglob("*") if p.is_file() and p.suffix.lower() in SUFFIXES))
    return found
