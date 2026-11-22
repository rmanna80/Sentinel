"""Sigma rule import: run community detection rules against Sentinel X telemetry.

`Sigma <https://github.com/SigmaHQ/sigma>`_ is the shared, vendor-neutral format detection engineers publish
rules in - several thousand of them, each a YAML file describing one behaviour over one kind of log. This
module reads those files and turns the ones it understands into rules for our engine, so coverage can grow by
pointing Sentinel at a folder instead of by hand-writing a class per technique.

What is supported, deliberately stated because a detection you only think you have is worse than none:

* **Log sources** - Windows rules whose ``category`` is one our Sysmon collector produces (process creation,
  network connection, registry set, file create/delete, image load, process access, remote thread, DNS query,
  WMI). Rules for other products, or for Windows channels we do not collect, are skipped.
* **Fields** - the Sysmon field names listed in ``FIELDS``. A rule that tests a field we do not capture is
  skipped whole, because evaluating it would silently never match.
* **Matching** - plain values with ``*``/``?`` wildcards, lists (any-of), and the modifiers ``contains``,
  ``startswith``, ``endswith``, ``all``, ``re``, ``cidr``, ``windash``, ``exists``, ``cased`` and the numeric
  comparisons. Everything is case-insensitive unless ``cased``, as Sigma specifies.
* **Conditions** - ``and``, ``or``, ``not``, parentheses, and ``1 of`` / ``all of`` with name patterns or
  ``them``.

Not supported, and reported per rule by :func:`load_sigma_rules` rather than guessed at: aggregations and
correlations (``| count()``, ``timeframe``), keyword-only selections, and the encoding modifiers
(``base64``, ``utf16``, ...). A Sigma rule is a single-event match; it does not use the process tree beyond
looking up a parent's command line.

Rules are data from a folder you choose. They are parsed with a safe YAML loader and can only match events;
the one thing worth knowing is that a rule's regular expressions run against your telemetry, so import rules
from a source you trust.
"""

from __future__ import annotations

import argparse
import ipaddress
import re
import sys
import threading
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from fnmatch import fnmatchcase
from pathlib import Path
from typing import Any

import yaml
from sentinel_core.models import SEVERITY_RANK, Confidence, Severity
from sentinel_core.telemetry import Detection, EventKind, TelemetryEvent

from .engine import Engine
from .process_tree import ProcessTree
from .rules import Emit, Rule

MAX_RULE_BYTES = 256 * 1024
MAX_REGEX_LENGTH = 2000


class SigmaUnsupported(Exception):
    """This rule uses something the importer does not implement; the message says what."""


# --------------------------------------------------------------------------- log sources and fields

CATEGORIES: dict[str, EventKind] = {
    "process_creation": EventKind.PROCESS_CREATE,
    "network_connection": EventKind.NETWORK_CONNECT,
    "registry_set": EventKind.REGISTRY_SET,
    "registry_event": EventKind.REGISTRY_SET,
    "file_event": EventKind.FILE_WRITE,
    "file_delete": EventKind.FILE_DELETE,
    "image_load": EventKind.IMAGE_LOAD,
    "process_access": EventKind.PROCESS_ACCESS,
    "create_remote_thread": EventKind.REMOTE_THREAD,
    "dns_query": EventKind.DNS_QUERY,
    "wmi_event": EventKind.WMI_SUBSCRIPTION,
}

Getter = Callable[[TelemetryEvent, ProcessTree], Any]


def _detail(key: str) -> Getter:
    return lambda e, _t: e.details.get(key)


def _attr(name: str) -> Getter:
    return lambda e, _t: getattr(e, name)


def _parent_command_line(event: TelemetryEvent, tree: ProcessTree) -> Any:
    recorded = event.details.get("parent_command_line")
    if recorded:
        return recorded
    parent = tree.get(event.parent_guid)
    return parent.command_line if parent else None


def _target_object(event: TelemetryEvent, _tree: ProcessTree) -> Any:
    if not event.registry_path:
        return None
    return f"{event.registry_path}\\{event.registry_value}" if event.registry_value else event.registry_path


def _registry_details(event: TelemetryEvent, _tree: ProcessTree) -> Any:
    raw = event.details.get("value_raw")
    if raw is not None:
        return raw
    value = event.details.get("value")
    return f"DWORD (0x{value:08x})" if isinstance(value, int) else value


def _granted_access(event: TelemetryEvent, _tree: ProcessTree) -> Any:
    mask = event.details.get("granted_access")
    return f"0x{mask:x}" if isinstance(mask, int) else None


def _initiated(event: TelemetryEvent, _tree: ProcessTree) -> Any:
    return None if event.direction is None else ("true" if event.direction == "outbound" else "false")


# Sysmon field name -> how to read it from one of our events. A rule naming a field absent from this table is
# skipped, never half-evaluated.
FIELDS: dict[str, Getter] = {
    "Image": _attr("image"), "CommandLine": _attr("command_line"), "User": _attr("user"),
    "ProcessId": _attr("pid"), "ParentImage": _attr("parent_image"), "ParentProcessId": _attr("parent_pid"),
    "ParentCommandLine": _parent_command_line, "OriginalFileName": _detail("original_file_name"),
    "CurrentDirectory": _detail("current_directory"), "IntegrityLevel": _detail("integrity_level"),
    "Hashes": _detail("hashes"), "Description": _detail("description"), "Product": _detail("product"),
    "Company": _detail("company"),
    "DestinationIp": _attr("dest_ip"), "DestinationPort": _attr("dest_port"), "Protocol": _attr("protocol"),
    "DestinationHostname": _detail("dest_hostname"), "SourceIp": _detail("source_ip"), "Initiated": _initiated,
    "TargetObject": _target_object, "Details": _registry_details,
    "TargetFilename": _attr("file_path"), "ImageLoaded": _attr("file_path"),
    "Signed": _detail("signed"), "Signature": _detail("signature"),
    "SourceImage": _attr("image"), "TargetImage": _attr("target_image"), "GrantedAccess": _granted_access,
    "CallTrace": _detail("call_trace"), "StartModule": _detail("start_module"),
    "StartFunction": _detail("start_function"), "StartAddress": _detail("start_address"),
    "QueryName": _attr("dns_query"), "QueryResults": _detail("query_results"), "QueryStatus": _detail("query_status"),
    "Operation": _detail("operation"), "EventNamespace": _detail("namespace"), "Name": _detail("name"),
    "Query": _detail("query"), "Type": _detail("consumer_type"), "Destination": _detail("destination"),
    "Consumer": _detail("consumer"), "Filter": _detail("filter"),
}

# --------------------------------------------------------------------------- value matching

Predicate = Callable[[TelemetryEvent, ProcessTree], bool]
_STRING_MODIFIERS = {"contains", "startswith", "endswith"}
_NUMERIC = {"lt": lambda a, b: a < b, "lte": lambda a, b: a <= b, "gt": lambda a, b: a > b, "gte": lambda a, b: a >= b}
_KNOWN_MODIFIERS = _STRING_MODIFIERS | set(_NUMERIC) | {"all", "re", "cidr", "windash", "exists", "cased", "i", "m", "s"}
_DASHES = ("-", "/", "\N{EN DASH}", "\N{EM DASH}", "\N{HORIZONTAL BAR}")


def _unescape(pattern: str) -> tuple[str, bool]:
    """Apply Sigma's escaping and translate the result to a regular expression.

    In a Sigma value ``*`` and ``?`` are wildcards and the backslash escapes exactly three things: ``\\*``
    and ``\\?`` are a literal asterisk and question mark, and ``\\\\`` is one literal backslash. A
    backslash before anything else is just a backslash, which is why Windows paths can be written plainly.
    Returns ``(regex_source, has_wildcard)``; when there is no wildcard, ``regex_source`` is unused and the
    caller compares the literal text from :func:`_literal` directly.
    """
    out: list[str] = []
    wildcard = False
    i = 0
    while i < len(pattern):
        ch = pattern[i]
        if ch == "\\" and i + 1 < len(pattern) and pattern[i + 1] in "\\*?":
            out.append(re.escape(pattern[i + 1]))
            i += 2
            continue
        if ch == "*":
            out.append(".*")
            wildcard = True
        elif ch == "?":
            out.append(".")
            wildcard = True
        else:
            out.append(re.escape(ch))
        i += 1
    return "".join(out), wildcard


def _literal(pattern: str) -> str:
    """The plain text a wildcard-free Sigma value stands for, with its escapes resolved."""
    return re.sub(r"\\([\\*?])", r"\1", pattern)


def _string_test(kind: str | None, expected: str, cased: bool) -> Callable[[str], bool]:
    want = expected if cased else expected.lower()
    source, wildcard = _unescape(want)
    if wildcard:
        prefix = "" if kind in ("contains", "endswith") else r"\A"
        suffix = "" if kind in ("contains", "startswith") else r"\Z"
        compiled = re.compile(f"{prefix}{source}{suffix}", re.DOTALL)
        return lambda actual: compiled.search(actual) is not None
    text = _literal(want)
    if kind == "contains":
        return lambda actual: text in actual
    if kind == "startswith":
        return lambda actual: actual.startswith(text)
    if kind == "endswith":
        return lambda actual: actual.endswith(text)
    return lambda actual: actual == text


# A field's value for the event being evaluated: (raw value, its text, its lower-cased text).
_Seen = tuple[Any, str | None, str | None]
ValueTest = Callable[[_Seen], bool]


def _value_test(modifiers: list[str], expected: Any) -> ValueTest:
    """One expected value under a field's modifiers -> a test on the field's actual value."""
    cased = "cased" in modifiers
    kind = next((m for m in modifiers if m in _STRING_MODIFIERS), None)
    if expected is None:
        return lambda seen: seen[0] is None or seen[0] == ""
    if "re" in modifiers:
        if len(str(expected)) > MAX_REGEX_LENGTH:
            raise SigmaUnsupported("regular expression is too long")
        flags = (0 if cased else re.IGNORECASE) | (re.MULTILINE if "m" in modifiers else 0) | (
            re.DOTALL if "s" in modifiers else 0)
        if "i" in modifiers:
            flags |= re.IGNORECASE
        try:
            compiled = re.compile(str(expected), flags)
        except re.error as exc:
            raise SigmaUnsupported(f"invalid regular expression: {exc}") from exc
        return lambda seen: seen[1] is not None and compiled.search(seen[1]) is not None
    if "cidr" in modifiers:
        try:
            network = ipaddress.ip_network(str(expected), strict=False)
        except ValueError as exc:
            raise SigmaUnsupported(f"invalid CIDR: {expected}") from exc

        def in_network(seen: _Seen) -> bool:
            try:
                return ipaddress.ip_address(seen[1] or "") in network
            except ValueError:
                return False
        return in_network
    numeric = next((m for m in modifiers if m in _NUMERIC), None)
    if numeric:
        try:
            compare, bound = _NUMERIC[numeric], float(expected)
        except (TypeError, ValueError) as exc:
            raise SigmaUnsupported(f"'{numeric}' needs a number") from exc

        def numeric_test(seen: _Seen) -> bool:
            try:
                return compare(float(seen[0]), bound)
            except (TypeError, ValueError):
                return False
        return numeric_test

    texts = [str(expected)]
    if "windash" in modifiers:
        texts = list(dict.fromkeys(str(expected).replace("-", dash) for dash in _DASHES))
    tests = [_string_test(kind, text, cased) for text in texts]
    index = 1 if cased else 2

    def string_test(seen: _Seen) -> bool:
        text = seen[index]
        return text is not None and any(test(text) for test in tests)
    return string_test


class _FieldCache(threading.local):
    """Field values of the event currently being evaluated, so a thousand rules lower-case it once, not each."""

    event: TelemetryEvent | None = None
    values: dict[str, _Seen] = {}  # replaced, never mutated, when the event changes


_cache = _FieldCache()


def _seen(name: str, getter: Getter, event: TelemetryEvent, tree: ProcessTree) -> _Seen:
    if _cache.event is not event:
        _cache.event, _cache.values = event, {}
    seen = _cache.values.get(name)
    if seen is None:
        actual = getter(event, tree)
        text = None if actual is None else (str(actual).lower() if isinstance(actual, bool) else str(actual))
        seen = _cache.values[name] = (actual, text, None if text is None else text.lower())
    return seen


def _field_predicate(key: str, expected: Any) -> Predicate:
    name, *modifiers = key.split("|")
    unknown = [m for m in modifiers if m not in _KNOWN_MODIFIERS]
    if unknown:
        raise SigmaUnsupported(f"modifier '{unknown[0]}' is not supported")
    getter = FIELDS.get(name)
    if getter is None:
        raise SigmaUnsupported(f"field '{name}' is not captured by the collector")
    if "exists" in modifiers:
        want = bool(expected)
        return lambda e, t: (_seen(name, getter, e, t)[0] not in (None, "")) is want
    values = expected if isinstance(expected, list) else [expected]
    if not values:
        raise SigmaUnsupported(f"field '{name}' has an empty value list")
    tests = [_value_test(modifiers, v) for v in values]
    if len(tests) == 1:
        only = tests[0]
        return lambda e, t: only(_seen(name, getter, e, t))
    combine = all if "all" in modifiers else any

    def field_matches(event: TelemetryEvent, tree: ProcessTree) -> bool:
        seen = _seen(name, getter, event, tree)
        return combine(test(seen) for test in tests)
    return field_matches


def _selection_predicate(body: Any) -> Predicate:
    """A selection is a map (all fields must match) or a list of maps (any one map must match)."""
    if isinstance(body, dict):
        if not body:
            raise SigmaUnsupported("empty selection")
        parts = [_field_predicate(str(k), v) for k, v in body.items()]
        return lambda e, t: all(p(e, t) for p in parts)
    if isinstance(body, list) and body and all(isinstance(item, dict) for item in body):
        options = [_selection_predicate(item) for item in body]
        return lambda e, t: any(o(e, t) for o in options)
    raise SigmaUnsupported("keyword selections (values without a field name) are not supported")


# --------------------------------------------------------------------------- condition expressions

_TOKEN = re.compile(r"\(|\)|[^\s()]+")


class _ConditionParser:
    """Recursive descent over ``or`` < ``and`` < ``not`` < atom, where an atom may be ``N of pattern``."""

    def __init__(self, text: str, selections: dict[str, Predicate]) -> None:
        if "|" in text:
            raise SigmaUnsupported("aggregation conditions ('| count()' and similar) are not supported")
        self.tokens = _TOKEN.findall(text)
        self.pos = 0
        self.selections = selections

    def parse(self) -> Predicate:
        result = self._or()
        if self.pos != len(self.tokens):
            raise SigmaUnsupported(f"could not parse condition near '{self.tokens[self.pos]}'")
        return result

    def _peek(self) -> str | None:
        return self.tokens[self.pos].lower() if self.pos < len(self.tokens) else None

    def _take(self) -> str:
        if self.pos >= len(self.tokens):
            raise SigmaUnsupported("condition ends unexpectedly")
        self.pos += 1
        return self.tokens[self.pos - 1]

    def _or(self) -> Predicate:
        terms = [self._and()]
        while self._peek() == "or":
            self._take()
            terms.append(self._and())
        return terms[0] if len(terms) == 1 else (lambda e, t: any(term(e, t) for term in terms))

    def _and(self) -> Predicate:
        terms = [self._not()]
        while self._peek() == "and":
            self._take()
            terms.append(self._not())
        return terms[0] if len(terms) == 1 else (lambda e, t: all(term(e, t) for term in terms))

    def _not(self) -> Predicate:
        if self._peek() == "not":
            self._take()
            inner = self._not()
            return lambda e, t: not inner(e, t)
        return self._atom()

    def _atom(self) -> Predicate:
        word = self._take()
        lowered = word.lower()
        if word == "(":
            inner = self._or()
            if self._take() != ")":
                raise SigmaUnsupported("unbalanced parentheses in condition")
            return inner
        if lowered in ("all", "any") or lowered.isdigit():
            if self._peek() != "of":
                raise SigmaUnsupported(f"expected 'of' after '{word}'")
            self._take()
            return self._quantified(lowered, self._take())
        if word not in self.selections:
            raise SigmaUnsupported(f"condition refers to unknown selection '{word}'")
        return self.selections[word]

    def _quantified(self, quantity: str, pattern: str) -> Predicate:
        if pattern.lower() == "them":
            chosen = list(self.selections.values())
        else:
            chosen = [p for name, p in self.selections.items() if fnmatchcase(name, pattern)]
        if not chosen:
            raise SigmaUnsupported(f"no selection matches '{pattern}'")
        if quantity == "all":
            return lambda e, t: all(p(e, t) for p in chosen)
        needed = 1 if quantity == "any" else int(quantity)
        return lambda e, t: sum(1 for p in chosen if p(e, t)) >= needed


# --------------------------------------------------------------------------- rules

_LEVELS = {"informational": Severity.INFO, "low": Severity.LOW, "medium": Severity.MEDIUM,
           "high": Severity.HIGH, "critical": Severity.CRITICAL}
_TECHNIQUE_TAG = re.compile(r"^attack\.(t\d{4}(?:\.\d{3})?)$", re.IGNORECASE)
_SLUG = re.compile(r"[^a-z0-9_.\-]+")


@dataclass
class SigmaRule:
    """One imported Sigma rule: what it matches, and what to say when it does."""

    rule_id: str
    title: str
    kind: EventKind
    matches: Predicate
    severity: Severity = Severity.MEDIUM
    confidence: Confidence = Confidence.MEDIUM
    technique_ids: tuple[str, ...] = ()
    description: str = ""
    false_positives: tuple[str, ...] = ()
    source: str = ""


def parse_sigma_rule(document: dict[str, Any], source: str = "") -> SigmaRule:
    """Compile one parsed Sigma document. Raises :class:`SigmaUnsupported` with the reason when it cannot."""
    if not isinstance(document, dict) or "detection" not in document:
        raise SigmaUnsupported("not a detection rule")
    if document.get("correlation") or "action" in document:
        raise SigmaUnsupported("correlation and multi-part rules are not supported")
    logsource = document.get("logsource") or {}
    product = str(logsource.get("product") or "windows").lower()
    if product != "windows":
        raise SigmaUnsupported(f"product '{product}' is not collected")
    category = str(logsource.get("category") or "").lower()
    if category not in CATEGORIES:
        described = category or f"service '{logsource.get('service')}'"
        raise SigmaUnsupported(f"log source {described} is not collected")

    detection = document["detection"]
    if not isinstance(detection, dict):
        raise SigmaUnsupported("detection section is not a map")
    if "timeframe" in detection:
        raise SigmaUnsupported("timeframe (multi-event) rules are not supported")
    condition = detection.get("condition")
    if isinstance(condition, list):
        if len(condition) != 1:
            raise SigmaUnsupported("multiple conditions are not supported")
        condition = condition[0]
    if not isinstance(condition, str) or not condition.strip():
        raise SigmaUnsupported("rule has no condition")
    selections = {str(name): _selection_predicate(body) for name, body in detection.items() if name != "condition"}
    if not selections:
        raise SigmaUnsupported("rule has no selections")
    matches = _ConditionParser(condition, selections).parse()

    title = str(document.get("title") or "Untitled Sigma rule")
    identifier = _SLUG.sub("-", str(document.get("id") or title).lower()).strip("-")[:100] or "unnamed"
    level = str(document.get("level") or "medium").lower()
    techniques = tuple(dict.fromkeys(
        m.group(1).upper() for tag in (document.get("tags") or []) if (m := _TECHNIQUE_TAG.match(str(tag)))
    ))
    experimental = str(document.get("status") or "").lower() in ("experimental", "unsupported", "deprecated")
    return SigmaRule(
        rule_id=f"sigma.{identifier}", title=title[:300], kind=CATEGORIES[category], matches=matches,
        severity=_LEVELS.get(level, Severity.MEDIUM),
        confidence=Confidence.LOW if experimental else Confidence.MEDIUM,
        technique_ids=techniques[:20], description=str(document.get("description") or "").strip(),
        false_positives=tuple(str(f) for f in (document.get("falsepositives") or []) if f)[:8], source=source,
    )


@dataclass
class SigmaImport:
    """The outcome of importing a folder: what loaded, and what was skipped and why."""

    rules: list[SigmaRule] = field(default_factory=list)
    skipped: list[tuple[str, str]] = field(default_factory=list)  # (file, reason)

    def skip_reasons(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for _, reason in self.skipped:
            key = re.sub(r"'[^']*'", "'...'", reason)
            counts[key] = counts.get(key, 0) + 1
        return dict(sorted(counts.items(), key=lambda kv: -kv[1]))


def load_sigma_rules(paths: Iterable[str | Path], min_level: Severity = Severity.MEDIUM) -> SigmaImport:
    """Import every ``.yml``/``.yaml`` file under ``paths``. Nothing here raises for a bad rule; it is recorded.

    Rules below ``min_level`` are skipped by default: Sigma's ``low`` and ``informational`` rules describe
    activity that is normal on most machines and are meant for hunting, not for alerting.
    """
    result = SigmaImport()
    seen: set[str] = set()
    for root in paths:
        root = Path(root)
        files = [root] if root.is_file() else sorted([*root.rglob("*.yml"), *root.rglob("*.yaml")])
        for file in files:
            name = str(file)
            try:
                if file.stat().st_size > MAX_RULE_BYTES:
                    raise SigmaUnsupported("file is too large to be a rule")
                documents = [d for d in yaml.safe_load_all(file.read_text(encoding="utf-8")) if d]
                if len(documents) != 1:
                    raise SigmaUnsupported("correlation and multi-part rules are not supported")
                rule = parse_sigma_rule(documents[0], source=name)
                if SEVERITY_RANK[rule.severity] < SEVERITY_RANK[min_level]:
                    raise SigmaUnsupported(f"level '{rule.severity.value}' is below the import threshold")
                if rule.rule_id in seen:
                    raise SigmaUnsupported("duplicate rule id")
            except SigmaUnsupported as exc:
                result.skipped.append((name, str(exc)))
            except (yaml.YAMLError, OSError, UnicodeDecodeError, ValueError, TypeError) as exc:
                result.skipped.append((name, f"could not be read: {type(exc).__name__}"))
            else:
                seen.add(rule.rule_id)
                result.rules.append(rule)
    return result


class SigmaRuleSet(Rule):
    """All imported Sigma rules as one engine rule, indexed by event kind so each event meets only its own."""

    id = "sigma"
    title = "Imported Sigma rules"

    def __init__(self, rules: Iterable[SigmaRule]) -> None:
        self._by_kind: dict[EventKind, list[SigmaRule]] = {}
        for rule in rules:
            self._by_kind.setdefault(rule.kind, []).append(rule)

    def __len__(self) -> int:
        return sum(len(rules) for rules in self._by_kind.values())

    def observe(self, event: TelemetryEvent, tree: ProcessTree, emit: Emit) -> None:
        for rule in self._by_kind.get(event.kind, ()):
            try:
                hit = rule.matches(event, tree)
            except Exception:  # noqa: S112 - one misbehaving community rule must never stop the engine
                continue
            if hit:
                emit(self._detection(rule, event, tree))

    def _detection(self, rule: SigmaRule, event: TelemetryEvent, tree: ProcessTree) -> Detection:
        observed = event.command_line or event.registry_path or event.file_path or event.dns_query or event.image
        parts = [rule.description or "This event matched a community Sigma rule."]
        if observed:
            parts.append(f"Observed:\n    {observed}")
        if rule.false_positives:
            parts.append("Known benign causes listed by the rule's author: " + "; ".join(rule.false_positives) + ".")
        parts.append(f"Imported Sigma rule {rule.rule_id.removeprefix('sigma.')}. It matches a single event and "
                     "was written for general use, not for this machine; treat it as a lead to check.")
        detection = self._detect(
            tree=tree, events=[event], primary_guid=event.process_guid,
            summary=rule.title[:1000], explanation="\n\n".join(parts)[:8000],
            dedup_key=f"{rule.rule_id}:{event.process_guid}", severity=rule.severity,
            confidence=rule.confidence, technique_ids=rule.technique_ids,
        )
        return detection.model_copy(update={"rule_id": rule.rule_id, "title": rule.title})


def sigma_ruleset(paths: Iterable[str | Path], min_level: Severity = Severity.MEDIUM) -> tuple[SigmaRuleSet, SigmaImport]:
    """Convenience for callers that want an engine rule plus the import report."""
    imported = load_sigma_rules(paths, min_level)
    return SigmaRuleSet(imported.rules), imported


def level_from_name(name: str | None, default: Severity = Severity.HIGH) -> Severity:
    return _LEVELS.get(str(name or "").lower(), default)


def engine_with_sigma(paths: Iterable[str | Path], min_level: Severity = Severity.HIGH) -> tuple[Engine, SigmaImport]:
    """An engine running the built-in rules plus every importable Sigma rule under ``paths``.

    The default threshold here is ``high``: measured against the lab's benign scenarios, Sigma's ``medium``
    rules fire on ordinary administration far more often than its ``high`` ones do. Lower it when hunting.
    """
    from .rules import default_rules

    imported = load_sigma_rules(paths, min_level)
    rules = default_rules()
    if imported.rules:
        rules.append(SigmaRuleSet(imported.rules))
    return Engine(rules=rules), imported


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="sentinel-sigma",
        description="Check which Sigma rules in a folder Sentinel X can run, and why the rest are skipped.",
    )
    parser.add_argument("paths", nargs="+", type=Path, help="Sigma rule files or folders")
    parser.add_argument("--min-level", default="medium", choices=list(_LEVELS), help="lowest level to import")
    parser.add_argument("--list-skipped", action="store_true", help="print every skipped file with its reason")
    args = parser.parse_args(argv)

    imported = load_sigma_rules(args.paths, _LEVELS[args.min_level])
    total = len(imported.rules) + len(imported.skipped)
    print(f"{len(imported.rules)} of {total} rule files imported.")
    by_kind: dict[str, int] = {}
    for rule in imported.rules:
        by_kind[rule.kind.value] = by_kind.get(rule.kind.value, 0) + 1
    for kind, count in sorted(by_kind.items(), key=lambda kv: -kv[1]):
        print(f"  {count:>5}  {kind}")
    if imported.skipped:
        print("\nSkipped, by reason:")
        for reason, count in imported.skip_reasons().items():
            print(f"  {count:>5}  {reason}")
    if args.list_skipped:
        print()
        for file, reason in imported.skipped:
            print(f"{file}: {reason}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
