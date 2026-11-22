#!/usr/bin/env python3
"""Check the Sigma importer against the Sigma project's own recorded events.

The SigmaHQ repository ships, for hundreds of rules, a real event captured while the behaviour was performed
(``regression_data/``). Each sample names the rule that must match it. This script imports the rules, replays
every Sysmon sample through the rule it belongs to, and reports how many match - an answer to "does our
importer agree with the people who wrote the rules?" that does not depend on anything we wrote ourselves.

    git clone --depth 1 https://github.com/SigmaHQ/sigma C:\\dev\\sigma
    uv run python scripts/run_sigma_regression.py C:\\dev\\sigma

It also replays every sample through *all* imported rules plus the built-in ones and counts detections, as a
rough check that the engine survives real, messy telemetry.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

import yaml
from sentinel_agent.telemetry.sysmon import parse_evtx_json
from sentinel_core.models import Severity
from sentinel_detect import Engine, SuppressionList, default_rules
from sentinel_detect.process_tree import ProcessTree
from sentinel_detect.sigma import SigmaRuleSet, load_sigma_rules


def main() -> int:
    parser = argparse.ArgumentParser(description="Score the Sigma importer against SigmaHQ's regression samples.")
    parser.add_argument("sigma_repo", type=Path, help="path to a clone of https://github.com/SigmaHQ/sigma")
    parser.add_argument("--json", metavar="FILE", help="write the full result as JSON")
    parser.add_argument("--show-misses", action="store_true")
    args = parser.parse_args()

    rule_dirs = [d for d in (args.sigma_repo / n for n in ("rules", "rules-threat-hunting", "rules-emerging-threats"))
                 if d.is_dir()]
    imported = load_sigma_rules(rule_dirs, min_level=Severity.INFO)
    by_id = {r.rule_id: r for r in imported.rules}
    skipped_ids = {Path(f).name: reason for f, reason in imported.skipped}

    matched: list[str] = []
    missed: list[tuple[str, str]] = []
    not_imported = no_events = 0
    all_events = []
    for info in sorted((args.sigma_repo / "regression_data").rglob("info.yml")):
        meta = yaml.safe_load(info.read_text(encoding="utf-8")) or {}
        for rule_meta in meta.get("rule_metadata") or []:
            rule_id = f"sigma.{rule_meta.get('id')}"
            sample = info.parent / f"{rule_meta.get('id')}.json"
            if not sample.is_file():
                continue
            events = parse_evtx_json(sample.read_text(encoding="utf-8", errors="replace"))
            if not events:
                no_events += 1  # not Sysmon, or an event id we do not collect
                continue
            all_events.extend(events)
            rule = by_id.get(rule_id)
            if rule is None:
                not_imported += 1
                continue
            tree = ProcessTree()
            hit = False
            for event in events:
                tree.ingest(event)
                hit = hit or (event.kind is rule.kind and rule.matches(event, tree))
            (matched.append(rule_id) if hit else missed.append((rule_id, str(rule_meta.get("title")))))

    tested = len(matched) + len(missed)
    print("Sigma importer - regression against SigmaHQ recorded events\n")
    print(f"  rules imported: {len(imported.rules)} of {len(imported.rules) + len(imported.skipped)}")
    print(f"  samples with Sysmon events for an imported rule: {tested}")
    print(f"  matched by their own rule: {len(matched)} ({len(matched) / tested:.1%})" if tested else "  none tested")
    print(f"  samples skipped: {not_imported} (rule not imported), {no_events} (no events we collect)")

    engine = Engine(rules=[*default_rules(), SigmaRuleSet(imported.rules)], suppressions=SuppressionList([]))
    detections = engine.feed_stream(all_events)
    builtin = sorted({d.rule_id for d in detections if not d.rule_id.startswith("sigma.")})
    print(f"\n  full replay: {len(all_events)} recorded events -> {len(detections)} detections")
    print(f"  built-in rules that fired on recorded attacks: {', '.join(builtin) or 'none'}")
    if args.show_misses:
        print()
        for rule_id, title in missed:
            print(f"  MISS {rule_id}  {title}")
    if args.json:
        Path(args.json).write_text(json.dumps({
            "imported": len(imported.rules), "skipped": imported.skip_reasons(), "tested": tested,
            "matched": len(matched), "missed": [{"rule": r, "title": t} for r, t in missed],
            "replay_events": len(all_events), "replay_detections": len(detections), "builtin_fired": builtin,
        }, indent=2), encoding="utf-8")
    _ = skipped_ids
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
