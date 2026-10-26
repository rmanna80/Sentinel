"""Regenerate docs/checks.md from the agent's check registry.

    uv run python scripts/gen_checks_doc.py
"""

from __future__ import annotations

from pathlib import Path

from sentinel_agent.registry import default_registry

PROFILE_ORDER = ["posture", "inventory", "logs", "network", "malware"]


def main() -> None:
    registry = default_registry()
    lines = [
        "# Checks",
        "",
        "Generated from the agent's registry by `scripts/gen_checks_doc.py`. Every check is read-only. "
        "\"Admin\" checks are skipped (and listed with that reason) unless you run an elevated scan.",
        "",
    ]
    by_profile: dict[str, list] = {}
    for d in registry.descriptors():
        key = next((p for p in PROFILE_ORDER if p in d.profiles), d.profiles[0])
        by_profile.setdefault(key, []).append(d)
    titles = {"posture": "Posture", "inventory": "Inventory", "logs": "Logs", "network": "Network (needs targets in scope)",
              "malware": "Malware (needs folders you configure)"}
    for profile in PROFILE_ORDER:
        items = sorted(by_profile.get(profile, []), key=lambda d: d.id)
        if not items:
            continue
        lines += [f"## {titles[profile]}", "", "| Check | Platforms | Admin | What it reads |", "| --- | --- | --- | --- |"]
        for d in items:
            plats = ", ".join(p.value.title() for p in d.platforms)
            lines.append(f"| `{d.id}` — {d.title} | {plats} | {'Yes' if d.requires_elevation else 'No'} | "
                         f"{d.data_collected.replace('|', '/')} |")
        lines.append("")
    lines.append(f"Total: {len(registry)} checks.")
    out = Path(__file__).resolve().parent.parent / "docs" / "checks.md"
    out.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"wrote {out}")


if __name__ == "__main__":
    main()
