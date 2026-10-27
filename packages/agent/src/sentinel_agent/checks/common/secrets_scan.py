"""Read-only scan of the owner's own project folders for committed secrets and risky configuration.

This is the defensive capability ported from the Strix pentester: Sentinel only *reports* secrets it finds
in the folders the owner configured. It never exploits anything, and it never stores the secret values
themselves - only the file path, the matched line number and the name of the rule that fired.
"""

from __future__ import annotations

import os
import re
from typing import Any

from sentinel_core.checks import Check, CheckContext, SkipCheck
from sentinel_core.models import CheckOutput, Confidence, Finding, FindingKind, Platform, Severity

from ...context import PathNotAllowed
from .._util import finding, join_path

NO_PROJECTS = "No project folders configured. Add one with: sentinel-agent config --add-project-path <folder>"

MAX_FILES = 20_000
MAX_FILE_BYTES = 1_000_000
MATCH_CAP = 500

# Folders we never descend into: build output, dependency trees, caches, VCS internals.
_SKIP_DIRS = frozenset({
    ".git", "node_modules", ".venv", "venv", "__pycache__", "dist", "build", ".next", ".mypy_cache",
    ".ruff_cache", ".pytest_cache", "site-packages", "vendor", "target",
})

# Extensions whose files are text-ish enough to scan. ".env" is handled as a prefix as well (.env.local etc).
_TEXT_EXTS = frozenset({
    ".env", ".py", ".js", ".ts", ".tsx", ".jsx", ".json", ".yaml", ".yml", ".toml", ".ini", ".cfg",
    ".conf", ".properties", ".sh", ".ps1", ".tf", ".pem", ".key", ".txt", ".md",
})
# Well-known secret-bearing files that have no ordinary extension.
_KEY_EXACT_NAMES = frozenset({".npmrc", ".netrc", "id_rsa", "id_dsa", "id_ecdsa"})
_KEY_EXTS = frozenset({".pem", ".key"})
# .env files that are templates, not real credentials.
_ENV_EXCLUDE = frozenset({".env.example", ".env.sample", ".env.template"})

# --------------------------------------------------------------------------- detection patterns
# The empty alternative yields "-----BEGIN PRIVATE KEY-----"; the others keep the trailing space so
# "RSA"/"DSA"/... sit as their own word, e.g. "-----BEGIN RSA PRIVATE KEY-----".
_BEGIN_PRIVATE_KEY = re.compile(r"-----BEGIN (?:RSA |DSA |EC |OPENSSH |PGP |)PRIVATE KEY-----")
_AWS_ACCESS_KEY = re.compile(r"AKIA[0-9A-Z]{16}")
_AWS_SECRET_KEY = re.compile(r"(?i)aws_secret.{0,20}[=:].{0,4}[A-Za-z0-9/+]{40}")
_GITHUB_TOKEN = re.compile(r"gh[pousr]_[A-Za-z0-9]{36,}")
_SLACK_TOKEN = re.compile(r"xox[baprs]-[A-Za-z0-9-]{10,}")
_GOOGLE_API_KEY = re.compile(r"AIza[0-9A-Za-z_\-]{35}")
_GENERIC_SECRET = re.compile(
    r"(?i)(password|passwd|secret|api[_-]?key|token|client[_-]?secret)\s*[=:]\s*[\"']?([^\s\"']{8,})[\"']?")
_DEBUG = re.compile(
    r"(?i)(DEBUG\s*[=:]\s*True|FLASK_DEBUG\s*[=:]\s*1|app\.debug\s*=\s*True|NODE_ENV\s*[=:]\s*[\"']?development)")
_ENV_KEY = re.compile(r"^\s*(?:export\s+)?[A-Za-z_][A-Za-z0-9_]*\s*=")

# Values that look like a secret assignment but are plainly placeholders, env-var references or booleans.
_PLACEHOLDER_EXACT = frozenset({"changeme", "example", "placeholder", "redacted", "null", "none", "true", "false"})


def _is_placeholder(value: str) -> bool:
    v = value.strip().strip("\"'")
    low = v.lower()
    if low in _PLACEHOLDER_EXACT:
        return True
    if low.startswith(("your-", "your_", "<", "...")):
        return True
    if low.startswith("xxxx") or (v and set(low) <= {"x"}):
        return True
    return "${" in v or "os.environ" in low or "process.env" in low


def _match_generic(line: str) -> bool:
    m = _GENERIC_SECRET.search(line)
    return bool(m) and not _is_placeholder(m.group(2))


# Each matcher takes a line and returns whether that line matches the rule. Order matters only for output.
_MATCHERS: dict[str, Any] = {
    "private_key": lambda line: bool(_BEGIN_PRIVATE_KEY.search(line)),
    "aws_access_key": lambda line: bool(_AWS_ACCESS_KEY.search(line)),
    "aws_secret_key": lambda line: bool(_AWS_SECRET_KEY.search(line)),
    "github_token": lambda line: bool(_GITHUB_TOKEN.search(line)),
    "slack_token": lambda line: bool(_SLACK_TOKEN.search(line)),
    "google_api_key": lambda line: bool(_GOOGLE_API_KEY.search(line)),
    "generic_secret_assignment": _match_generic,
    "debug_enabled": lambda line: bool(_DEBUG.search(line)),
}

# Line rules run on ordinary code and config files, in this order.
_LINE_RULES_FULL = ("private_key", "aws_access_key", "aws_secret_key", "github_token", "slack_token",
                    "google_api_key", "generic_secret_assignment")
# The low-noise, high-confidence rules only (.md and .txt get just these).
_HIGH_CONF_RULES = ("private_key", "aws_access_key", "github_token", "slack_token")

_ALL_RULE_NAMES = (*_LINE_RULES_FULL, "debug_enabled", "committed_env_file", "committed_private_key_file",
                   "private_key_file")

# --------------------------------------------------------------------------- finding copy
_ROTATE = (
    "Remove the secret from the file, rotate it (it should be treated as compromised once committed), and move it "
    "to an untracked secrets store or environment variable. If it was committed to git, rewrite history with "
    "git filter-repo or BFG so it is not in past commits."
)

_RULES: dict[str, dict[str, Any]] = {
    "private_key": {
        "label": "Private key", "severity": Severity.HIGH, "kind": FindingKind.VERIFIED,
        "confidence": Confidence.HIGH, "remediation": _ROTATE,
        "impact": "A private key in a project folder can be copied by anyone with the files or the git history "
                  "and used to impersonate you or to decrypt traffic.",
    },
    "aws_access_key": {
        "label": "AWS access key ID", "severity": Severity.HIGH, "kind": FindingKind.VERIFIED,
        "confidence": Confidence.HIGH, "remediation": _ROTATE,
        "impact": "An AWS access key in your files can let someone use your AWS account, run up charges or reach "
                  "your data.",
    },
    "aws_secret_key": {
        "label": "AWS secret access key", "severity": Severity.HIGH, "kind": FindingKind.HEURISTIC,
        "confidence": Confidence.MEDIUM, "remediation": _ROTATE,
        "impact": "This looks like an AWS secret access key. Paired with the key ID it gives full programmatic "
                  "access to the AWS account.",
    },
    "github_token": {
        "label": "GitHub token", "severity": Severity.HIGH, "kind": FindingKind.VERIFIED,
        "confidence": Confidence.HIGH, "remediation": _ROTATE,
        "impact": "A GitHub token in your files can let someone read or push to your repositories as you.",
    },
    "slack_token": {
        "label": "Slack token", "severity": Severity.HIGH, "kind": FindingKind.VERIFIED,
        "confidence": Confidence.HIGH, "remediation": _ROTATE,
        "impact": "A Slack token in your files can let someone read or post in your workspace as you.",
    },
    "google_api_key": {
        "label": "Google API key", "severity": Severity.HIGH, "kind": FindingKind.HEURISTIC,
        "confidence": Confidence.MEDIUM, "remediation": _ROTATE,
        "impact": "A Google API key in your files can be used by others, which may run up billing or reach the "
                  "Google services it has access to.",
    },
    "generic_secret_assignment": {
        "label": "Possible hardcoded secret", "severity": Severity.MEDIUM, "kind": FindingKind.HEURISTIC,
        "confidence": Confidence.MEDIUM, "remediation": _ROTATE,
        "impact": "This looks like a password or key assigned in a file. If it is a real secret, anyone who reads "
                  "the file can use it. This rule is noisy, so confidence is medium - check whether the value is a "
                  "real secret or just a placeholder.",
    },
    "debug_enabled": {
        "label": "Debug mode enabled in config", "severity": Severity.LOW, "kind": FindingKind.HEURISTIC,
        "confidence": Confidence.LOW,
        "remediation": "Turn debug mode off in any configuration that ships or runs outside your own machine. Keep "
                       "it on only in local-only development files.",
        "impact": "Debug mode left on outside local development can leak stack traces, configuration and sometimes "
                  "an interactive console to anyone who can reach the app.",
    },
    "committed_env_file": {
        "label": "Tracked .env file", "severity": Severity.MEDIUM, "kind": FindingKind.VERIFIED,
        "confidence": Confidence.HIGH,
        "remediation": "Add .env to .gitignore and keep a .env.example with placeholder values instead.",
        "impact": ".env files usually hold real credentials. This one sits in a folder tracked by git, so its "
                  "contents are in the repository and its history.",
    },
    "committed_private_key_file": {
        "label": "Private key file", "severity": Severity.HIGH, "kind": FindingKind.VERIFIED,
        "confidence": Confidence.HIGH, "remediation": _ROTATE,
        "impact": "This file is a private key stored in a project folder. Anyone with the files or the git history "
                  "has the key.",
    },
    # Flagged by file name/extension without reading the file: Sentinel never opens .pem/.key files on a live
    # host. It may be a private key (remove and rotate it) or a public certificate (safe to ignore).
    "private_key_file": {
        "label": "Key file (.pem/.key) present", "severity": Severity.HIGH, "kind": FindingKind.HEURISTIC,
        "confidence": Confidence.MEDIUM,
        "remediation": "Sentinel did not open this file. If it is a private key committed to the project, remove it, "
                       "rotate it, and purge it from git history (git filter-repo / BFG). If it is a public "
                       "certificate it is fine to keep.",
        "impact": "A .pem/.key file is in a project folder. If it holds a private key, anyone with the files or the "
                  "git history has it.",
    },
}


def _ext(name: str) -> str:
    return os.path.splitext(name)[1].lower()


def _is_env_file(name: str) -> bool:
    return name == ".env" or name.startswith(".env.")


def _is_key_file(name: str) -> bool:
    return name in _KEY_EXACT_NAMES or _ext(name) in _KEY_EXTS


def _should_read(name: str) -> bool:
    return _is_key_file(name) or _is_env_file(name) or _ext(name) in _TEXT_EXTS


def _looks_like_prod_config(name: str) -> bool:
    low = name.lower()
    return _is_env_file(name) or any(k in low for k in ("prod", "settings", "config"))


def _rules_for(name: str) -> tuple[str, ...]:
    if _ext(name) in (".md", ".txt"):
        return _HIGH_CONF_RULES
    rules = _LINE_RULES_FULL
    if _looks_like_prod_config(name):
        rules = (*rules, "debug_enabled")
    return rules


def _walk_project(ctx: CheckContext, root: str) -> tuple[list[tuple[str, str, str, bool]], bool]:
    """Depth-first walk of one configured folder using ``ctx.list_dir``.

    Returns ``(files, truncated)`` where ``files`` is ``[(relpath, fullpath, name, in_repo)]`` for every regular
    file found. ``relpath`` always uses ``/`` separators and is relative to ``root``. ``in_repo`` is true when the
    file (or an ancestor) sits in a folder that contains a ``.git`` directory. Unreadable sub-folders are skipped;
    an unreadable ``root`` raises OSError, which the caller turns into a SkipCheck.
    """
    root_names = ctx.list_dir(root)  # OSError here propagates to the caller
    files: list[tuple[str, str, str, bool]] = []
    truncated = False
    stack: list[tuple[str, str, list[str], bool]] = [(root, "", root_names, False)]
    while stack and len(files) < MAX_FILES:
        current, relbase, names, parent_in_repo = stack.pop()
        here_in_repo = parent_in_repo or (".git" in names)
        for name in sorted(names):
            if len(files) >= MAX_FILES:
                truncated = True
                break
            if name in _SKIP_DIRS:
                continue
            child = join_path(current, name)
            childrel = f"{relbase}/{name}" if relbase else name
            try:
                child_names = ctx.list_dir(child)
            except PermissionError:
                continue  # an unreadable sub-folder: skip it, do not guess at its contents
            except PathNotAllowed:
                # An allowed root but a denied leaf (a .pem/.key/*_key file the agent must never read). Record
                # it by name so its existence can still be reported; it is never opened.
                files.append((childrel, child, name, here_in_repo))
                continue
            except OSError:
                files.append((childrel, child, name, here_in_repo))  # not a directory -> a regular file
                continue
            stack.append((child, childrel, child_names, here_in_repo))
    if stack:
        truncated = True
    return files, truncated


class SecretsScan(Check):
    id = "dev.secrets"
    version = "1"
    title = "No secrets or risky config are committed in your projects"
    category = "configuration"
    platforms = frozenset({Platform.WINDOWS, Platform.LINUX})
    profiles = frozenset({"inventory"})
    timeout_seconds = 120.0
    data_collected = (
        "File names and matched line numbers in your configured project folders; the matched secret values "
        "themselves are never stored."
    )

    def run(self, ctx: CheckContext) -> CheckOutput:
        folders = [str(p) for p in ctx.config.get("project_paths", []) or []]
        if not folders:
            raise SkipCheck(NO_PROJECTS)

        counts: dict[str, int] = dict.fromkeys(_ALL_RULE_NAMES, 0)
        matches: list[dict[str, Any]] = []
        seen: set[str] = set()
        findings: list[Finding] = []
        stats = {"total": 0, "read": 0, "skipped_not_text": 0, "skipped_large": 0, "unreadable": 0}
        walk_truncated = False

        def record(rule: str, project: str, relpath: str, lineno: int, **extra: Any) -> None:
            key = f"{project}:{relpath}:{rule}:{lineno}"
            if key in seen:
                return
            seen.add(key)
            counts[rule] += 1
            if len(matches) < MATCH_CAP:
                entry = {"project": project, "file": relpath, "line": lineno, "rule": rule}
                entry.update(extra)
                matches.append(entry)
            meta = _RULES[rule]
            title = f"{meta['label']} found in {relpath} (line {lineno})" if lineno else f"{meta['label']}: {relpath}"
            findings.append(finding(
                f"dev.secrets.{rule}", key, title[:300], meta["severity"], meta["impact"], meta["remediation"],
                confidence=meta["confidence"], kind=meta["kind"], category="configuration",
            ))

        for project in folders:
            try:
                files, truncated = _walk_project(ctx, project)
            except (PathNotAllowed, OSError) as exc:
                raise SkipCheck(f"The configured project folder {project} could not be read: {str(exc)[:200]}") from exc
            walk_truncated = walk_truncated or truncated
            for relpath, path, name, in_repo in sorted(files):
                stats["total"] += 1
                if not _should_read(name):
                    stats["skipped_not_text"] += 1
                    continue
                is_env = _is_env_file(name)
                is_key = _is_key_file(name)
                raw: str | None
                try:
                    raw = ctx.read_text(path, max_bytes=MAX_FILE_BYTES + 1)
                except (PathNotAllowed, OSError):
                    raw = None
                    stats["unreadable"] += 1
                else:
                    if len(raw) > MAX_FILE_BYTES:
                        raw = None
                        stats["skipped_large"] += 1
                    else:
                        stats["read"] += 1

                env_keys: int | None = None
                if raw is not None:
                    for lineno, line in enumerate(raw.splitlines(), start=1):
                        for rule in _rules_for(name):
                            if _MATCHERS[rule](line):
                                record(rule, project, relpath, lineno)
                    if is_key and _BEGIN_PRIVATE_KEY.search(raw):
                        record("committed_private_key_file", project, relpath, 0)
                    # a readable key file WITHOUT a private-key header is a certificate/public key -> not flagged
                    if is_env:
                        env_keys = sum(1 for ln in raw.splitlines()
                                       if _ENV_KEY.match(ln) and not ln.lstrip().startswith("#"))

                if is_key and raw is None:
                    # could not read it (the allowlist refuses key files on a live host, or it was too large):
                    # report its existence by name, without ever opening it
                    record("private_key_file", project, relpath, 0)

                if is_env and name not in _ENV_EXCLUDE and in_repo:
                    record("committed_env_file", project, relpath, 0, keys=env_keys)

        evidence = [ctx.evidence("file_metadata", "configured project folders", {
            "folders": folders,
            "files_total": stats["total"],
            "files_read": stats["read"],
            "files_skipped_not_text": stats["skipped_not_text"],
            "files_skipped_large": stats["skipped_large"],
            "files_unreadable": stats["unreadable"],
            "walk_truncated": walk_truncated,
            "counts": counts,
            "matches": matches,
            "note": "Only file paths, line numbers and rule names are recorded. The matched secret values "
                    "themselves are never stored.",
        })]
        return CheckOutput(evidence=evidence, findings=findings)
