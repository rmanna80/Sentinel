"""Turn a pytest JUnit XML report into GitHub Actions error annotations.

Annotations are readable through the GitHub API (check runs), so failures can be read without
downloading the raw job log. GitHub keeps at most 10 error annotations per step: the first one lists
every failed test id, the rest carry the first lines of individual failures.

    python scripts/ci_annotate.py report.xml
"""

from __future__ import annotations

import sys
from pathlib import Path

from defusedxml import ElementTree


def _escape(text: str) -> str:
    return text.replace("%", "%25").replace("\r", "").replace("\n", "%0A")


def main(path: str) -> int:
    report = Path(path)
    if not report.exists():
        print(f"::error title=pytest::No report at {path}; pytest probably failed to start")
        return 0
    root = ElementTree.parse(report).getroot()
    failures: list[tuple[str, str]] = []
    for case in root.iter("testcase"):
        for tag in ("failure", "error"):
            node = case.find(tag)
            if node is not None:
                test_id = f"{case.get('classname', '')}::{case.get('name', '')}"
                detail = (node.get("message") or "") + "\n" + (node.text or "")
                failures.append((test_id, detail))
    if not failures:
        return 0
    listing = "\n".join(test_id for test_id, _ in failures)
    print(f"::error title={len(failures)} failed tests::{_escape(listing[:20000])}")
    for test_id, detail in failures[:9]:
        tail = "\n".join(detail.strip().splitlines()[-40:])
        print(f"::error title={_escape(test_id[:200])}::{_escape(tail[:6000])}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1] if len(sys.argv) > 1 else "report.xml"))
