"""The engine's own jobs: staying quiet on benign activity, suppression, throttling, deterministic replay."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from pydantic import ValidationError
from sentinel_core.models import Confidence, FindingKind, Severity
from sentinel_core.telemetry import Detection, EventKind, TelemetryEvent
from sentinel_detect import Engine, StreamBuilder, Suppression, SuppressionList, default_suppressions

EXPLORER = r"C:\Windows\explorer.exe"
PWSH = r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
WINWORD = r"C:\Program Files\Microsoft Office\root\Office16\winword.exe"
RUN_KEY = r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"


def _detection(image: str, rule_id: str = "exec.office_spawns_interpreter") -> Detection:
    event = TelemetryEvent(kind=EventKind.PROCESS_CREATE, ts=datetime(2026, 1, 1, tzinfo=UTC),
                           host="H", seq=0, pid=1, process_guid="g", image=image)
    return Detection(rule_id=rule_id, title="t", summary="s", explanation="e", severity=Severity.HIGH,
                     confidence=Confidence.HIGH, kind=FindingKind.HEURISTIC, host="H",
                     first_ts=event.ts, last_ts=event.ts, dedup_key=f"{rule_id}:g", events=[event])


# --------------------------------------------------------------------------- benign activity


def test_ordinary_admin_session_is_silent():
    # Explorer launches PowerShell, it talks to an internal host, and sets a benign per-user value.
    b = StreamBuilder()
    b.process_create("E", EXPLORER)
    b.process_create("P", PWSH, parent_guid="E", parent_image=EXPLORER, command_line="Get-Service")
    b.network_connect("P", "10.0.0.20", 443, image=PWSH)
    b.registry_set("P", r"HKCU\Software\Contoso\App", "LastRun", value=1, image=PWSH)
    assert Engine().feed_stream(b.events) == []


# --------------------------------------------------------------------------- suppression


def test_suppression_validator_requires_a_subject():
    with pytest.raises(ValidationError):
        Suppression(reason="no subject given")


def test_suppression_drops_only_the_named_rule():
    b = StreamBuilder()
    b.process_create("W", WINWORD, parent_guid="E", parent_image=EXPLORER)
    b.process_create("P", PWSH, parent_guid="W", parent_image=WINWORD)
    supp = SuppressionList([Suppression(reason="sanctioned macro tool", rule_id="exec.office_spawns_interpreter",
                                        image="*winword.exe")])
    assert Engine(suppressions=supp).feed_stream(b.events) == []
    # a suppression for a different rule leaves this one alone
    other = SuppressionList([Suppression(reason="x", rule_id="persist.autorun_registry", image="*winword.exe")])
    assert Engine(suppressions=other).feed_stream(b.events)


def test_default_suppression_matches_by_path_prefix():
    allowed = _detection(r"C:\Program Files\Sentinel\sentinel-agent.exe")
    elsewhere = _detection(r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe")
    supp = default_suppressions()
    assert supp.suppresses(allowed) is not None
    assert supp.suppresses(elsewhere) is None


def test_image_glob_is_case_and_slash_insensitive():
    supp = SuppressionList([Suppression(reason="x", image="powershell.exe")])
    assert supp.suppresses(_detection(r"C:\Windows\System32\WindowsPowerShell\v1.0\POWERSHELL.EXE")) is not None


# --------------------------------------------------------------------------- throttling


def test_repeated_behaviour_is_throttled_then_re_emitted_after_the_window():
    start = datetime(2026, 1, 1, 12, 0, 0, tzinfo=UTC)
    b = StreamBuilder(start=start)
    b.process_create("P", PWSH, parent_guid="E", parent_image=EXPLORER)
    # three writes to the same autorun key from the same process
    b.registry_set("P", RUN_KEY, "A", value="x", image=PWSH, ts=start + timedelta(seconds=1))
    b.registry_set("P", RUN_KEY, "B", value="x", image=PWSH, ts=start + timedelta(seconds=10))  # within window
    b.registry_set("P", RUN_KEY, "C", value="x", image=PWSH, ts=start + timedelta(hours=2))  # past window
    autoruns = [d for d in Engine().feed_stream(b.events) if d.rule_id == "persist.autorun_registry"]
    assert len(autoruns) == 2  # second write throttled, third re-emitted after the hour


# --------------------------------------------------------------------------- determinism


def test_replay_is_order_independent():
    b = StreamBuilder()
    b.process_create("W", WINWORD, parent_guid="E", parent_image=EXPLORER)
    b.process_create("P", PWSH, parent_guid="W", parent_image=WINWORD)
    b.network_connect("P", "8.8.8.8", 443, image=PWSH)
    b.registry_set("P", RUN_KEY, "Updater", value="x", image=PWSH)
    in_order = {d.rule_id for d in Engine().feed_stream(b.events)}
    shuffled = {d.rule_id for d in Engine().feed_stream(list(reversed(b.events)))}
    assert in_order == shuffled
    assert "intrusion.suspicious_exec_chain" in in_order
