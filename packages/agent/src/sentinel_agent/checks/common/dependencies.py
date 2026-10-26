"""Pinned dependencies of the owner's development projects (for vulnerability matching on the server)."""

from __future__ import annotations

import json
import re
from typing import Any

from sentinel_core.checks import Check, CheckContext, SkipCheck
from sentinel_core.models import CheckOutput, Platform, SoftwareItem

from ...context import PathNotAllowed
from .._util import join_path

NO_PROJECTS = "No project folders configured. Add one with: sentinel-agent config --add-project-path <folder>"
# PEP 508 name, optional [extras], then exactly "==" and a version (no wildcards).
_PINNED = re.compile(r"^(?P<name>[A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?)\s*(?:\[[^\]]*\])?\s*==\s*"
                     r"(?P<version>[A-Za-z0-9][A-Za-z0-9.+!_-]*)\s*$")


def normalize_pypi(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def parse_requirements(text: str) -> tuple[list[tuple[str, str]], int]:
    """Return ([(name, version)], number of requirement lines that are not exact pins)."""
    pins: list[tuple[str, str]] = []
    unpinned = 0
    text = re.sub(r"\\\r?\n", " ", text)  # pip joins lines that end with a backslash (common with --hash)
    for raw in text.splitlines():
        line = raw.split(" #", 1)[0].strip()
        if not line or line.startswith("#") or line.startswith("-"):
            continue  # comments, -r/-c includes, -e editables, --index-url and other options
        line = line.split(";", 1)[0].strip()  # environment markers
        line = re.split(r"\s+--hash", line, maxsplit=1)[0].strip()
        if "://" in line or line.startswith((".", "/")) or " @ " in line:
            unpinned += 1
            continue
        m = _PINNED.match(line)
        if m and "*" not in m.group("version"):
            pins.append((normalize_pypi(m.group("name")), m.group("version")))
        else:
            unpinned += 1
    return pins, unpinned


def parse_package_lock(text: str) -> tuple[list[tuple[str, str]], int | None]:
    """Return ([(name, version)], lockfileVersion). Only lockfile v2/v3 ``packages`` maps are read."""
    data = json.loads(text)
    version = data.get("lockfileVersion") if isinstance(data, dict) else None
    packages = data.get("packages") if isinstance(data, dict) else None
    if version not in (2, 3) or not isinstance(packages, dict):
        return [], version if isinstance(version, int) else None
    out: list[tuple[str, str]] = []
    for path, meta in packages.items():
        if not path or not isinstance(meta, dict) or "node_modules/" not in path:
            continue  # "" is the root project; workspace folders have no node_modules/ prefix
        if meta.get("link"):
            continue  # symlink to a workspace package, listed under its own path
        name = meta.get("name") or path.rsplit("node_modules/", 1)[-1]
        ver = meta.get("version")
        if isinstance(name, str) and isinstance(ver, str) and ver:
            out.append((name, ver))
    return out, version


class ProjectDependencies(Check):
    id = "dev.dependencies"
    version = "1"
    title = "Dependencies of your development projects"
    category = "inventory"
    platforms = frozenset({Platform.WINDOWS, Platform.LINUX})
    profiles = frozenset({"inventory"})
    timeout_seconds = 60.0
    data_collected = (
        "Package names and exact versions from requirements.txt and package-lock.json in the project folders you "
        "configured (nothing else in those folders is read)"
    )

    def run(self, ctx: CheckContext) -> CheckOutput:
        folders = [str(p) for p in ctx.config.get("project_paths") or []]
        if not folders:
            raise SkipCheck(NO_PROJECTS)
        items: dict[tuple[str, str, str, str], SoftwareItem] = {}
        report: list[dict[str, Any]] = []
        for folder in folders:
            entry: dict[str, Any] = {"folder": folder}
            try:
                names = set(ctx.list_dir(folder))
            except (PathNotAllowed, OSError) as exc:
                entry["error"] = str(exc)[:200]
                report.append(entry)
                continue
            if "requirements.txt" in names:
                path = join_path(folder, "requirements.txt")
                try:
                    pins, unpinned = parse_requirements(ctx.read_text(path))
                    entry["requirements.txt"] = {"pinned": len(pins), "not_pinned": unpinned}
                    for name, ver in pins:
                        items[("PyPI", name, ver, folder)] = SoftwareItem(
                            name=name, version=ver, ecosystem="PyPI", source="requirements.txt", location=folder)
                except (PathNotAllowed, OSError) as exc:
                    entry["requirements.txt"] = {"error": str(exc)[:200]}
            if "package-lock.json" in names:
                path = join_path(folder, "package-lock.json")
                try:
                    pkgs, lock_version = parse_package_lock(ctx.read_text(path, max_bytes=20_000_000))
                    entry["package-lock.json"] = {"lockfileVersion": lock_version, "packages": len(pkgs)}
                    if lock_version not in (2, 3):
                        entry["package-lock.json"]["note"] = "Only lockfileVersion 2 and 3 are read"
                    for name, ver in pkgs:
                        items[("npm", name, ver, folder)] = SoftwareItem(
                            name=name, version=ver, ecosystem="npm", source="package-lock.json", location=folder)
                except (PathNotAllowed, OSError, ValueError) as exc:
                    entry["package-lock.json"] = {"error": str(exc)[:200]}
            if "requirements.txt" not in names and "package-lock.json" not in names:
                entry["note"] = "No requirements.txt or package-lock.json in this folder"
            report.append(entry)
        evidence = [ctx.evidence("file_metadata", "configured project folders", {
            "projects": report, "dependencies": len(items),
            "note": "Only exact pins (name==version) are listed from requirements.txt; ranges cannot be matched "
                    "to advisories reliably.",
        })]
        software = sorted(items.values(), key=lambda s: (s.location or "", s.ecosystem, s.name, s.version or ""))
        return CheckOutput(evidence=evidence, software=software)
