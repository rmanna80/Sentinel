#!/usr/bin/env python3
"""Run the Sentinel X detection lab: score the engine against the labelled corpus and report.

    uv run python scripts/run_detection_lab.py            # print a scorecard
    uv run python scripts/run_detection_lab.py --json out.json   # also write the machine-readable report
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from sentinel_detect import default_corpus, measure_throughput, score


def main() -> int:
    parser = argparse.ArgumentParser(description="Score the Sentinel X detection engine against the corpus.")
    parser.add_argument("--json", metavar="FILE", help="write the full scorecard as JSON")
    parser.add_argument("--throughput", type=int, default=5000, help="events to use for the throughput benchmark")
    args = parser.parse_args()

    card = score(default_corpus())
    perf = measure_throughput(args.throughput)
    report = card.as_dict() | {"throughput": perf}

    print("Sentinel X — detection lab\n")
    c = report["counts"]
    print(f"  precision {card.precision:.0%}   recall {card.recall:.0%}   "
          f"(TP {c['tp']}  FP {c['fp']}  FN {c['fn']}  TN {c['tn']})")
    cov = report["technique_coverage"]
    print(f"  ATT&CK techniques covered: {cov['covered']}/{cov['total']}")
    lat = report["latency_seconds"]
    if lat.get("count"):
        print(f"  detection latency (s): min {lat['min']:.0f}  median {lat['median']:.0f}  max {lat['max']:.0f}")
    print(f"  throughput: {perf['events_per_second']:,.0f} events/s  ({perf['per_event_us']:.1f} us/event)\n")

    for r in report["scenarios"]:
        verdict = "DETECTED" if r["detected"] else ("quiet" if r["label"] == "benign" else "MISSED")
        flag = "  <-- false positive" if (r["label"] == "benign" and r["unexpected"]) else ""
        print(f"  [{r['label']:<9}] {r['name']:<22} {verdict}{flag}")

    if args.json:
        Path(args.json).write_text(json.dumps(report, indent=2), encoding="utf-8")
        print(f"\nWrote {args.json}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
