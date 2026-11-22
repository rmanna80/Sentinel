#!/usr/bin/env python3
"""Replay recorded telemetry through Sentinel X and report what it would have said.

Two questions this answers, and they need different recordings:

* **Does it catch real attacks?** Replay a public attack dataset with ``--label malicious``. Each file is one
  recorded technique; the report is how many files produced at least one detection.

      uv run python scripts/replay_dataset.py C:\\datasets\\attacks --label malicious

* **How noisy is it on my machine?** Export a few days of your own Sysmon log and replay it with
  ``--label benign``. Every detection is then a false positive (or something you should look at), and the
  number that matters is detections per day.

      wevtutil qe Microsoft-Windows-Sysmon/Operational /f:xml > C:\\datasets\\my-week.xml
      uv run python scripts/replay_dataset.py C:\\datasets\\my-week.xml --label benign

Add ``--sigma DIR`` to include imported Sigma rules. Reads .jsonl, Sysmon .xml exports and EVTX-as-JSON.
"""

from __future__ import annotations

import argparse
import json
from collections import Counter
from pathlib import Path

from sentinel_agent.telemetry.dataset import find_recordings, load_recording
from sentinel_detect import Engine
from sentinel_detect.sigma import engine_with_sigma, level_from_name


def main() -> int:
    parser = argparse.ArgumentParser(description="Replay recorded telemetry through the Sentinel X engine.")
    parser.add_argument("paths", nargs="+", help="recording files or folders")
    parser.add_argument("--label", choices=["malicious", "benign"], required=True,
                        help="what the recordings contain, so the result can be scored")
    parser.add_argument("--sigma", metavar="DIR", action="append", help="also run Sigma rules from this folder")
    parser.add_argument("--sigma-level", default="high")
    parser.add_argument("--json", metavar="FILE", help="write the full result as JSON")
    parser.add_argument("--show-quiet", action="store_true", help="list malicious recordings nothing fired on")
    args = parser.parse_args()

    def new_engine() -> Engine:
        if args.sigma:
            return engine_with_sigma(args.sigma, level_from_name(args.sigma_level))[0]
        return Engine()

    files = find_recordings(args.paths)
    by_rule: Counter[str] = Counter()
    detected: list[str] = []
    quiet: list[str] = []
    unreadable: list[str] = []
    total_events = 0
    span_seconds = 0.0
    for file in files:
        try:
            events = load_recording(file)
        except (ValueError, OSError) as exc:
            unreadable.append(f"{file}: {exc}")
            continue
        if not events:
            unreadable.append(f"{file}: no Sysmon events Sentinel X collects")
            continue
        total_events += len(events)
        stamps = [e.ts for e in events]
        span_seconds += (max(stamps) - min(stamps)).total_seconds()
        detections = new_engine().feed_stream(events)  # a fresh engine per recording: no state leaks between them
        by_rule.update(d.rule_id for d in detections)
        (detected if detections else quiet).append(str(file))

    read = len(detected) + len(quiet)
    total = sum(by_rule.values())
    print(f"Sentinel X - replay of {read} {args.label} recording(s), {total_events} events\n")
    if not read:
        print("  nothing readable was found.")
    elif args.label == "malicious":
        print(f"  recordings with at least one detection: {len(detected)} of {read} ({len(detected) / read:.1%})")
        print("  (a recording with no detection is a miss only if it holds a technique a rule is meant to cover)")
    else:
        days = span_seconds / 86400
        print(f"  detections on benign activity: {total} across {len(detected)} of {read} recording(s)")
        if days >= 0.04:  # under an hour of data a per-day rate is noise
            print(f"  covering {days:.1f} day(s): {total / days:.1f} false positives per day")
        else:
            print("  the recordings cover under an hour, too little for a per-day rate")
    if by_rule:
        print("\n  detections by rule:")
        for rule_id, count in by_rule.most_common(25):
            print(f"    {count:>5}  {rule_id}")
    if unreadable:
        print(f"\n  {len(unreadable)} file(s) skipped:")
        for line in unreadable[:10]:
            print(f"    {line}")
    if args.show_quiet and args.label == "malicious":
        print()
        for name in quiet:
            print(f"  QUIET {name}")
    if args.json:
        Path(args.json).write_text(json.dumps({
            "label": args.label, "recordings": read, "events": total_events, "with_detections": len(detected),
            "detections": total, "span_days": round(span_seconds / 86400, 3), "by_rule": dict(by_rule),
            "quiet": quiet, "skipped": unreadable,
        }, indent=2), encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
