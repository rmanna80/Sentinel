"""Behavioural detection ingestion (device) and the triage API (user)."""

from __future__ import annotations

from sentinel_detect import Engine, StreamBuilder

EXPLORER = r"C:\Windows\explorer.exe"
PWSH = r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
WINWORD = r"C:\Program Files\Microsoft Office\root\Office16\winword.exe"
RUN_KEY = r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"


def _detections():
    b = StreamBuilder()
    b.process_create("W", WINWORD, parent_guid="E", parent_image=EXPLORER)
    b.process_create("P", PWSH, parent_guid="W", parent_image=WINWORD, command_line="powershell -enc AAA")
    b.network_connect("P", "8.8.8.8", 443, image=PWSH)
    b.registry_set("P", RUN_KEY, "Updater", value="x", image=PWSH)
    dets = Engine().feed_stream(b.events)
    assert {d.rule_id for d in dets} >= {"intrusion.suspicious_exec_chain", "exec.office_spawns_interpreter"}
    return dets


def test_ingest_list_and_summary(make_agent, browser):
    agent = make_agent([])
    agent.client.send_detections(_detections())

    page = browser.get("/api/behavior/detections").json()
    assert page["total"] == 3
    severities = {d["severity"] for d in page["items"]}
    assert "critical" in severities
    # every stored detection is tied to the device that reported it
    assert all(d["device_id"] == agent.device_id for d in page["items"])

    summary = browser.get("/api/behavior/summary").json()
    assert summary["total"] == 3 and summary["new"] == 3
    assert summary["by_severity"]["critical"] >= 1 and summary["by_severity"]["high"] >= 1
    assert summary["hosts"] == 1
    assert any(r["rule_id"] == "intrusion.suspicious_exec_chain" for r in summary["top_rules"])


def test_repeated_behaviour_upserts_and_counts(make_agent, browser):
    agent = make_agent([])
    agent.client.send_detections(_detections())
    agent.client.send_detections(_detections())  # same dedup keys again
    page = browser.get("/api/behavior/detections").json()
    assert page["total"] == 3  # not six: upserted
    assert all(d["count"] == 2 for d in page["items"])


def test_detail_carries_evidence(make_agent, browser):
    agent = make_agent([])
    agent.client.send_detections(_detections())
    chain = next(d for d in browser.get("/api/behavior/detections").json()["items"]
                 if d["rule_id"] == "intrusion.suspicious_exec_chain")
    detail = browser.get(f"/api/behavior/detections/{chain['id']}").json()
    assert len(detail["events"]) == 3  # the three triggering events travel as evidence
    assert detail["process_tree"] and detail["explanation"]


def test_dismiss_hides_from_default_view(make_agent, browser):
    agent = make_agent([])
    agent.client.send_detections(_detections())
    first = browser.get("/api/behavior/detections").json()["items"][0]
    r = browser.patch(f"/api/behavior/detections/{first['id']}", json={"status": "dismissed"})
    assert r.status_code == 200 and r.json()["status"] == "dismissed"
    assert browser.get("/api/behavior/detections").json()["total"] == 2  # default hides dismissed
    assert browser.get("/api/behavior/detections", params={"status": "all"}).json()["total"] == 3
    assert browser.get("/api/behavior/summary").json()["dismissed"] == 1


def test_detections_require_authentication(anon):
    assert anon.get("/api/behavior/detections").status_code == 401
    assert anon.post("/api/agent/detections", json=[]).status_code == 401  # device token required
