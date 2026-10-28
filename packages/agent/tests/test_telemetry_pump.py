"""The run-loop telemetry step: collect -> correlate (persistent engine) -> ship."""

from __future__ import annotations

from datetime import UTC, datetime

from sentinel_agent.telemetry.pump import run_cycle
from sentinel_detect import Engine, StreamBuilder

EXPLORER = r"C:\Windows\explorer.exe"
PWSH = r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
WINWORD = r"C:\Program Files\Microsoft Office\root\Office16\winword.exe"
RUN_KEY = r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"


class StubCollector:
    def __init__(self, events):
        self._events = events

    def collect(self):
        return self._events


class StubClient:
    def __init__(self):
        self.shipped = []

    def send_detections(self, detections):
        self.shipped.extend(detections)


def test_run_cycle_ships_detections():
    b = StreamBuilder()
    b.process_create("W", WINWORD, parent_guid="E", parent_image=EXPLORER)
    b.process_create("P", PWSH, parent_guid="W", parent_image=WINWORD, command_line="powershell -enc AAA")
    b.network_connect("P", "8.8.8.8", 443, image=PWSH)
    b.registry_set("P", RUN_KEY, "Updater", value="x", image=PWSH)
    client = StubClient()
    dets = run_cycle(StubCollector(b.events), Engine(), client)
    assert any(d.rule_id == "intrusion.suspicious_exec_chain" for d in dets)
    assert client.shipped == dets


def test_run_cycle_is_silent_on_benign():
    b = StreamBuilder()
    b.process_create("E", EXPLORER)
    b.process_create("P", PWSH, parent_guid="E", parent_image=EXPLORER, command_line="Get-Process")
    client = StubClient()
    assert run_cycle(StubCollector(b.events), Engine(), client) == []
    assert client.shipped == []


def test_engine_state_persists_across_cycles():
    # The chain spans two collect() calls; only a long-lived engine can correlate across them.
    engine, client = Engine(), StubClient()

    c1 = StreamBuilder(start=datetime(2026, 1, 1, 12, 0, 0, tzinfo=UTC))
    c1.process_create("W", WINWORD, parent_guid="E", parent_image=EXPLORER)
    c1.process_create("P", PWSH, parent_guid="W", parent_image=WINWORD)
    c1.network_connect("P", "8.8.8.8", 443, image=PWSH)
    assert not any(d.rule_id == "intrusion.suspicious_exec_chain"
                   for d in run_cycle(StubCollector(c1.events), engine, client))  # no tamper yet

    c2 = StreamBuilder(start=datetime(2026, 1, 1, 12, 0, 30, tzinfo=UTC))  # within the window
    c2.registry_set("P", RUN_KEY, "Updater", value="x", image=PWSH)
    run_cycle(StubCollector(c2.events), engine, client)
    assert any(d.rule_id == "intrusion.suspicious_exec_chain" for d in client.shipped)
