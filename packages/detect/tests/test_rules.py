"""Each rule in isolation, plus the benign cases that must stay quiet.

Rules run through a real :class:`Engine` (so the process tree and dispatch are exercised too) but with
suppression switched off, so these tests measure the rule logic alone. The benign streams are as important
as the malicious ones: a detection engine that cannot stay quiet during ordinary administration is useless.
"""

from __future__ import annotations

from datetime import timedelta

from sentinel_detect import Engine, StreamBuilder, SuppressionList

# recognisable image paths
EXPLORER = r"C:\Windows\explorer.exe"
PWSH = r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
CMD = r"C:\Windows\System32\cmd.exe"
MSHTA = r"C:\Windows\System32\mshta.exe"
WINWORD = r"C:\Program Files\Microsoft Office\root\Office16\winword.exe"
OUTLOOK = r"C:\Program Files\Microsoft Office\root\Office16\outlook.exe"
SVCHOST = r"C:\Windows\System32\svchost.exe"
SERVICES = r"C:\Windows\System32\services.exe"
TEMP_EXE = r"C:\Users\alice\AppData\Local\Temp\payload.exe"

RUN_KEY = r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
WINLOGON = r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
DEFENDER_RT = r"HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection"
FIREWALL = r"HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\StandardProfile"

EXTERNAL = "8.8.8.8"
INTERNAL = "10.0.0.5"


def run(events, **engine_kw):
    return Engine(suppressions=SuppressionList([]), **engine_kw).feed_stream(events)


def ids(detections):
    return {d.rule_id for d in detections}


def one(detections, rule_id):
    matches = [d for d in detections if d.rule_id == rule_id]
    assert len(matches) == 1, f"expected exactly one {rule_id}, got {[d.rule_id for d in detections]}"
    return matches[0]


# --------------------------------------------------------------------------- office -> interpreter


def test_office_spawning_interpreter_fires():
    b = StreamBuilder()
    b.process_create("W", WINWORD, parent_guid="E", parent_image=EXPLORER)
    b.process_create("P", PWSH, parent_guid="W", parent_image=WINWORD, command_line="powershell -enc AAA")
    det = one(run(b.events), "exec.office_spawns_interpreter")
    assert det.severity.value == "high"
    assert "T1566" in det.technique_ids and det.technique_names  # mapped to names


def test_outlook_spawning_mshta_fires():
    b = StreamBuilder()
    b.process_create("O", OUTLOOK, parent_guid="E", parent_image=EXPLORER)
    b.process_create("M", MSHTA, parent_guid="O", parent_image=OUTLOOK)
    assert "exec.office_spawns_interpreter" in ids(run(b.events))


def test_explorer_spawning_powershell_is_quiet():
    b = StreamBuilder()
    b.process_create("E", EXPLORER)
    b.process_create("P", PWSH, parent_guid="E", parent_image=EXPLORER, command_line="Get-Process")
    assert "exec.office_spawns_interpreter" not in ids(run(b.events))


def test_office_spawning_non_interpreter_is_quiet():
    b = StreamBuilder()
    b.process_create("W", WINWORD, parent_guid="E", parent_image=EXPLORER)
    b.process_create("C", r"C:\Program Files\Microsoft Office\root\Office16\ai.exe",
                     parent_guid="W", parent_image=WINWORD)  # a normal Office helper, not a shell
    assert run(b.events) == []


# --------------------------------------------------------------------------- autorun persistence


def test_interpreter_writing_run_key_fires():
    b = StreamBuilder()
    b.process_create("P", PWSH, parent_guid="E", parent_image=EXPLORER)
    b.registry_set("P", RUN_KEY, "Updater", value=r"C:\Users\Public\u.exe", image=PWSH)
    det = one(run(b.events), "persist.autorun_registry")
    assert det.severity.value == "medium" and "T1547.001" in det.technique_ids


def test_process_from_temp_writing_run_key_fires():
    b = StreamBuilder()
    b.process_create("X", TEMP_EXE, parent_guid="E", parent_image=EXPLORER)
    b.registry_set("X", RUN_KEY, "Svc", value="x", image=TEMP_EXE)
    assert "persist.autorun_registry" in ids(run(b.events))


def test_service_host_writing_run_key_is_quiet():
    # Legitimate system components touch autoruns constantly; only an unusual author is flagged.
    b = StreamBuilder()
    b.process_create("S", SVCHOST, parent_guid="SV", parent_image=SERVICES)
    b.registry_set("S", RUN_KEY, "SomeService", value="x", image=SVCHOST)
    assert "persist.autorun_registry" not in ids(run(b.events))


def test_winlogon_shell_value_is_autorun():
    b = StreamBuilder()
    b.process_create("P", PWSH, parent_guid="E", parent_image=EXPLORER)
    b.registry_set("P", WINLOGON, "Shell", value=r"explorer.exe,evil.exe", image=PWSH)
    assert "persist.autorun_registry" in ids(run(b.events))


# --------------------------------------------------------------------------- defense tampering


def test_defender_realtime_disabled_fires():
    b = StreamBuilder()
    b.process_create("P", PWSH, parent_guid="E", parent_image=EXPLORER)
    b.registry_set("P", DEFENDER_RT, "DisableRealtimeMonitoring", value=1, image=PWSH)
    det = one(run(b.events), "defense.security_tooling_disabled")
    assert det.severity.value == "high" and "T1562.001" in det.technique_ids


def test_defender_realtime_reenabled_is_quiet():
    b = StreamBuilder()
    b.process_create("P", PWSH, parent_guid="E", parent_image=EXPLORER)
    b.registry_set("P", DEFENDER_RT, "DisableRealtimeMonitoring", value=0, image=PWSH)  # value 0 = protection ON
    assert "defense.security_tooling_disabled" not in ids(run(b.events))


def test_defender_disable_without_captured_value_is_flagged():
    # If the collector didn't capture the value, a write to a disable-flag is treated as suspicious.
    b = StreamBuilder()
    b.process_create("P", PWSH, parent_guid="E", parent_image=EXPLORER)
    b.registry_set("P", DEFENDER_RT, "DisableRealtimeMonitoring", image=PWSH)  # no value
    assert "defense.security_tooling_disabled" in ids(run(b.events))


def test_firewall_disabled_fires_but_enabled_is_quiet():
    b = StreamBuilder()
    b.process_create("P", PWSH, parent_guid="E", parent_image=EXPLORER)
    b.registry_set("P", FIREWALL, "EnableFirewall", value=0, image=PWSH)
    assert "defense.security_tooling_disabled" in ids(run(b.events))

    b2 = StreamBuilder()
    b2.process_create("P", PWSH, parent_guid="E", parent_image=EXPLORER)
    b2.registry_set("P", FIREWALL, "EnableFirewall", value=1, image=PWSH)
    assert "defense.security_tooling_disabled" not in ids(run(b2.events))


# --------------------------------------------------------------------------- the correlation chain


def _malicious_chain(builder: StreamBuilder, *, net_from: str = "P", reg_from: str = "P") -> StreamBuilder:
    builder.process_create("W", WINWORD, parent_guid="E", parent_image=EXPLORER)
    builder.process_create("P", PWSH, parent_guid="W", parent_image=WINWORD, command_line="powershell -enc AAA")
    builder.process_create("C", CMD, parent_guid="P", parent_image=PWSH)  # a descendant
    builder.network_connect(net_from, EXTERNAL, 443, image=CMD if net_from == "C" else PWSH)
    builder.registry_set(reg_from, RUN_KEY, "Updater", value=r"C:\Users\Public\u.exe",
                         image=CMD if reg_from == "C" else PWSH)
    return builder


def test_full_chain_fires_critical():
    det = one(run(_malicious_chain(StreamBuilder()).events), "intrusion.suspicious_exec_chain")
    assert det.severity.value == "critical"
    assert len(det.events) == 3  # the three triggering events travel as evidence
    assert det.process_tree  # ancestry context attached
    assert "T1059" in det.technique_ids


def test_chain_attributes_a_descendants_activity():
    # The outbound connection and the registry change come from cmd.exe, a child of the interpreter.
    dets = run(_malicious_chain(StreamBuilder(), net_from="C", reg_from="C").events)
    assert "intrusion.suspicious_exec_chain" in ids(dets)


def test_chain_fires_regardless_of_stage_order():
    b = StreamBuilder()
    b.process_create("W", WINWORD, parent_guid="E", parent_image=EXPLORER)
    b.process_create("P", PWSH, parent_guid="W", parent_image=WINWORD)
    b.registry_set("P", DEFENDER_RT, "DisableRealtimeMonitoring", value=1, image=PWSH)  # tamper first
    b.network_connect("P", EXTERNAL, 8080, image=PWSH)  # then network
    assert "intrusion.suspicious_exec_chain" in ids(run(b.events))


def test_chain_needs_all_three_stages():
    b = StreamBuilder()  # spawn + tamper but no outbound connection
    b.process_create("W", WINWORD, parent_guid="E", parent_image=EXPLORER)
    b.process_create("P", PWSH, parent_guid="W", parent_image=WINWORD)
    b.registry_set("P", RUN_KEY, "Updater", value="x", image=PWSH)
    assert "intrusion.suspicious_exec_chain" not in ids(run(b.events))


def test_chain_requires_an_unusual_parent():
    # Same three actions, but the interpreter was launched normally (by explorer) — no chain.
    b = StreamBuilder()
    b.process_create("E", EXPLORER)
    b.process_create("P", PWSH, parent_guid="E", parent_image=EXPLORER)
    b.network_connect("P", EXTERNAL, 443, image=PWSH)
    b.registry_set("P", DEFENDER_RT, "DisableRealtimeMonitoring", value=1, image=PWSH)
    out = ids(run(b.events))
    assert "intrusion.suspicious_exec_chain" not in out
    assert "defense.security_tooling_disabled" in out  # the tamper itself is still reported on its own merits


def test_chain_ignores_internal_only_connections():
    b = StreamBuilder()
    b.process_create("W", WINWORD, parent_guid="E", parent_image=EXPLORER)
    b.process_create("P", PWSH, parent_guid="W", parent_image=WINWORD)
    b.network_connect("P", INTERNAL, 445, image=PWSH)  # lateral, not egress
    b.registry_set("P", RUN_KEY, "Updater", value="x", image=PWSH)
    assert "intrusion.suspicious_exec_chain" not in ids(run(b.events))


def test_chain_expires_outside_the_window():
    b = StreamBuilder()
    start = b._ts
    b.process_create("W", WINWORD, parent_guid="E", parent_image=EXPLORER)
    b.process_create("P", PWSH, parent_guid="W", parent_image=WINWORD)
    # network and tamper arrive 20 minutes later — past the 10-minute default window
    b.network_connect("P", EXTERNAL, 443, image=PWSH, ts=start + timedelta(minutes=20))
    b.registry_set("P", RUN_KEY, "Updater", value="x", image=PWSH, ts=start + timedelta(minutes=20, seconds=1))
    assert "intrusion.suspicious_exec_chain" not in ids(run(b.events))
