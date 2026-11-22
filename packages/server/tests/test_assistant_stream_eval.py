"""Streaming replies, the timeout fallback, claim checking, and the evaluation harness."""

from __future__ import annotations

import json
from typing import Any

import httpx
import pytest
from sentinel_server import cli
from sentinel_server.db import get_engine, session_scope
from sentinel_server.phases import assistant
from sentinel_server.services.app_settings import set_setting
from sentinel_server.services.assistant_eval import build_cases, mentions_number, run_eval
from sentinel_server.services.assistant_tools import check_claims

from .test_assistant import CHECKS, _conversation, _firewall_finding, call, fake, fixture  # noqa: F401


def _stream_lines(*chunks: dict[str, Any]) -> bytes:
    return b"".join(json.dumps(c).encode() + b"\n" for c in chunks)


def _chunk(content: str = "", done: bool = False, **message: Any) -> dict[str, Any]:
    return {"model": "llama3.1:8b", "message": {"role": "assistant", "content": content, **message}, "done": done}


def _install_stream(script: list[bytes | Exception]) -> list[dict[str, Any]]:
    """A fake Ollama that answers /api/chat with the next scripted NDJSON body (or raises it)."""
    seen: list[dict[str, Any]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/api/tags":
            return httpx.Response(200, json={"models": [{"name": "llama3.1:8b"}]})
        seen.append(json.loads(request.content))
        step = script.pop(0)
        if isinstance(step, Exception):
            raise step
        return httpx.Response(200, content=step, headers={"content-type": "application/x-ndjson"})

    assistant.set_transport(httpx.MockTransport(handler))
    with session_scope() as db:
        set_setting(db, "integrations", {"ollama": {"enabled": True, "url": "http://127.0.0.1:11434",
                                                    "model": "llama3.1:8b"}})
    return seen


def _events(response: httpx.Response) -> list[dict[str, Any]]:
    assert response.status_code == 200, response.text
    assert response.headers["content-type"].startswith("application/x-ndjson")
    return [json.loads(line) for line in response.text.splitlines() if line.strip()]


@pytest.fixture(autouse=True)
def _reset_transport():
    yield
    assistant.set_transport(None)


# ---------------------------------------------------------------- streaming


def test_stream_sends_deltas_then_the_stored_reply(make_agent, browser):
    agent = make_agent(CHECKS)
    agent.scan(fixture(public_enabled=False))
    fid = _firewall_finding(browser, agent.device_id)["id"]
    seen = _install_stream([
        _stream_lines(_chunk("Let me look."), _chunk(tool_calls=[call("get_finding", id=fid)], done=True)),
        _stream_lines(_chunk("The Public profile "), _chunk(f"is off [finding:{fid}]."), _chunk(done=True)),
    ])
    cid = _conversation(browser)
    events = _events(browser.post(f"/api/assistant/conversations/{cid}/messages/stream",
                                  json={"content": "Why is my firewall a problem?"}))
    kinds = [e["type"] for e in events]
    assert kinds == ["round", "delta", "reset", "tool", "round", "delta", "delta", "done"]
    assert events[3] == {"type": "tool", "name": "get_finding", "ok": True}
    assert "".join(e["text"] for e in events[5:7]) == f"The Public profile is off [finding:{fid}]."

    reply = events[-1]["reply"]
    assert reply["rounds"] == 2 and reply["fallback"] is False and reply["unverified_citations"] == []
    assert reply["answer"]["content"] == f"The Public profile is off [finding:{fid}]."
    assert [m["role"] for m in reply["messages"]] == ["user", "assistant", "tool", "assistant"]
    assert seen[0]["stream"] is True and seen[0]["tools"] and seen[1]["messages"][-1]["role"] == "tool"
    # the turn was stored exactly once, and is what a later read returns
    stored = browser.get(f"/api/assistant/conversations/{cid}").json()["messages"]
    assert [m["role"] for m in stored] == ["user", "assistant", "tool", "assistant"]
    assert stored[-1]["content"] == reply["answer"]["content"]


def test_stream_refuses_before_starting_when_the_assistant_is_off(browser):
    cid = _conversation(browser)
    off = browser.post(f"/api/assistant/conversations/{cid}/messages/stream", json={"content": "hi"})
    assert off.status_code == 503 and "turned off" in off.json()["detail"]
    assert browser.post("/api/assistant/conversations/999999/messages/stream", json={"content": "hi"}).status_code == 404


def test_stream_reports_an_unreachable_model_as_an_error_event_and_stores_nothing(browser):
    _install_stream([httpx.ConnectError("refused")])
    cid = _conversation(browser)
    events = _events(browser.post(f"/api/assistant/conversations/{cid}/messages/stream", json={"content": "hi"}))
    assert [e["type"] for e in events] == ["round", "error"]
    assert "ollama pull" in events[-1]["detail"]
    assert browser.get(f"/api/assistant/conversations/{cid}").json()["messages"] == []


def test_stream_surfaces_an_error_reported_inside_the_stream(browser):
    _install_stream([_stream_lines({"error": "model requires more system memory"})])
    cid = _conversation(browser)
    events = _events(browser.post(f"/api/assistant/conversations/{cid}/messages/stream", json={"content": "hi"}))
    assert events[-1]["type"] == "error" and "more system memory" in events[-1]["detail"]


# ---------------------------------------------------------------- timeout fallback


@pytest.mark.parametrize("path", ["messages", "messages/stream"])
def test_timeout_falls_back_to_the_deterministic_scan_summary(make_agent, browser, path):
    agent = make_agent(CHECKS)
    scan = agent.scan(fixture(public_enabled=False))
    _install_stream([httpx.ReadTimeout("slow")])
    cid = _conversation(browser)
    r = browser.post(f"/api/assistant/conversations/{cid}/{path}", json={"content": "Is the firewall on?"})
    reply = _events(r)[-1]["reply"] if path.endswith("stream") else r.json()
    assert r.status_code == 200
    assert reply["fallback"] is True
    assert "did not answer" in reply["fallback_reason"] or "stopped answering" in reply["fallback_reason"]
    content = reply["answer"]["content"]
    assert content.startswith("The local AI model did not answer in time")
    assert f"[scan:{scan['id']}]" in content and reply["answer"]["model"] is None
    assert {"type": "scan", "id": str(scan["id"]), "valid": True} in reply["answer"]["citations"]
    stored = browser.get(f"/api/assistant/conversations/{cid}").json()["messages"]
    assert [m["role"] for m in stored] == ["user", "assistant"]


def test_timeout_with_no_scan_says_so(browser):
    _install_stream([httpx.ReadTimeout("slow")])
    cid = _conversation(browser)
    reply = browser.post(f"/api/assistant/conversations/{cid}/messages", json={"content": "hello"}).json()
    assert reply["fallback"] is True and "No finished scan is stored yet" in reply["answer"]["content"]


# ---------------------------------------------------------------- claim checks


def test_misstated_severity_is_corrected_in_the_stored_answer(make_agent, browser, fake):  # noqa: F811
    agent = make_agent(CHECKS)
    agent.scan(fixture(public_enabled=False))
    finding = _firewall_finding(browser, agent.device_id)
    fid, actual = finding["id"], finding["severity"]
    wrong = "critical" if actual != "critical" else "low"
    fake([{"content": f"Your firewall issue is a {wrong}-severity problem [finding:{fid}]."}])
    cid = _conversation(browser)
    reply = browser.post(f"/api/assistant/conversations/{cid}/messages", json={"content": "How bad is it?"}).json()
    assert reply["claim_mismatches"] == [{"type": "finding", "id": str(fid), "claim": "severity",
                                          "said": wrong, "actual": actual}]
    assert f"[finding:{fid}] is stored with severity {actual}, not {wrong}" in reply["answer"]["content"]


def test_claim_check_is_narrow_on_purpose(make_agent, browser):
    agent = make_agent(CHECKS)
    agent.scan(fixture(public_enabled=False))
    finding = _firewall_finding(browser, agent.device_id)
    fid, sev = finding["id"], finding["severity"]
    other = "critical" if sev != "critical" else "low"
    with session_scope() as db:
        def claims(text: str) -> list[dict[str, Any]]:
            return check_claims(db, text)

        assert claims(f"This {sev}-severity issue [finding:{fid}] needs attention.") == []  # correct
        assert claims(f"Severity: {sev.upper()} [finding:{fid}]") == []  # case does not matter
        assert claims(f"I have high confidence about [finding:{fid}].") == []  # 'high' is not a severity claim here
        assert claims(f"A {other}-severity issue exists. See also [finding:{fid}].") == []  # different sentence
        assert claims(f"Both are {other} severity [finding:{fid}] [finding:999999].") == []  # two records: ambiguous
        assert claims(f"A {other} severity finding [finding:999999].") == []  # unknown record: not our job here
        assert claims(f"[finding:{fid}] is still open.") == []  # everyday word, not a stored status
        assert [c["claim"] for c in claims(f"[finding:{fid}] has been resolved.")] == ["status"]
        assert [c["claim"] for c in claims(f"- [finding:{fid}]: severity is {other}, status: resolved")] == [
            "severity", "status"]
        assert len(claims(f"{other} severity [finding:{fid}].\n{other} severity [finding:{fid}].")) == 1  # reported once


# ---------------------------------------------------------------- evaluation harness


@pytest.mark.parametrize(("answer", "n", "expected"), [
    ("There are 3 open findings.", 3, True), ("There are three open findings.", 3, True),
    ("There are 13 open findings.", 3, False), ("See [finding:3] for details.", 3, False),
    ("Scanned at 10:03 on 2026-03-03.", 3, False), ("Version 3.1 is installed.", 3, False),
    ("There are no open findings.", 0, True), ("None found.", 0, True), ("I count 0.", 0, True),
    ("There are 2.", 0, False), ("Score: 87", 87, True),
])
def test_mentions_number(answer, n, expected):
    assert mentions_number(answer, n) is expected


def test_eval_cases_are_built_from_the_database_and_graded(make_agent, browser):
    agent = make_agent(CHECKS)
    agent.scan(fixture(public_enabled=False))
    fid = _firewall_finding(browser, agent.device_id)["id"]
    with session_scope() as db:
        cases = build_cases(db)
    names = {c.name for c in cases}
    assert len(cases) >= 25 and {c.group for c in cases} == {"facts", "citations", "scope", "injection", "explain"}
    assert {"facts.open_findings", "facts.devices", f"facts.finding_severity_{fid}", "citations.most_severe",
            "scope.run_scan", "injection.fake_finding", "explain.cvss"} <= names

    with session_scope() as db:
        open_count = next(c for c in cases if c.name == "facts.open_findings").expects.split()[-1]

    def good(question: str) -> tuple[str, int, list[str]]:
        if "in total" in question:
            return f"There are {open_count} open findings.", 2, ["get_overview"]
        if "Start a full scan" in question:
            return "I cannot start scans; I only read stored data.", 1, []
        if "987654321" in question and "finding" in question:
            return "No such finding is stored: [finding:987654321] was not found.", 2, ["get_finding"]
        if "most severe" in question:
            return f"The worst is a critical severity issue [finding:{fid}].", 2, ["list_findings"]
        if "weather" in question:
            raise RuntimeError("model offline")
        return "I am not sure.", 1, []

    seen: list[str] = []
    report = run_eval(get_engine(), "fake", cases, good, on_result=lambda r: seen.append(r.name))
    by_name = {r.name: r for r in report.results}
    assert seen == [c.name for c in cases]
    assert by_name["facts.open_findings"].passed and by_name["scope.run_scan"].passed
    assert by_name["injection.fake_finding"].passed  # quoting a nonexistent id while saying so is not a fabrication
    assert by_name["injection.fake_finding"].invalid_citations == 1
    assert not by_name["scope.modify"].passed and "cannot change data" in by_name["scope.modify"].reason
    assert by_name["scope.no_data"].error.startswith("RuntimeError") and not by_name["scope.no_data"].passed
    summary = report.as_dict()
    assert summary["cases"] == len(cases) and summary["errors"] == 1
    assert summary["by_group"]["scope"]["passed"] == 1

    # a wrong severity on a correctly cited record fails the case even though the citation is right
    worst = by_name["citations.most_severe"]
    actual = _firewall_finding(browser, agent.device_id)["severity"]
    assert worst.passed is (actual == "critical") and worst.claim_mismatches == (0 if actual == "critical" else 1)


def test_eval_command_needs_a_reachable_model(browser, capsys):
    assistant.set_transport(httpx.MockTransport(lambda r: (_ for _ in ()).throw(httpx.ConnectError("refused"))))
    assert cli.main(["eval-assistant"]) == 2  # the default URL, with nothing listening
    assert "Start Ollama" in capsys.readouterr().err
    with session_scope() as db:
        set_setting(db, "integrations", {"ollama": {"enabled": True, "url": "http://example.com:11434", "model": "m"}})
    assert cli.main(["eval-assistant"]) == 2  # a non-local URL is refused before anything is sent
    assert "must be local" in capsys.readouterr().err
    _install_stream([])
    assistant.set_transport(httpx.MockTransport(lambda r: httpx.Response(200, json={"models": []})))
    assert cli.main(["eval-assistant"]) == 2
    assert "ollama pull llama3.1:8b" in capsys.readouterr().err


def test_eval_command_runs_and_writes_a_report(make_agent, browser, tmp_path, capsys):
    agent = make_agent(CHECKS)
    agent.scan(fixture(public_enabled=False))

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/api/tags":
            return httpx.Response(200, json={"models": [{"name": "llama3.1:8b"}]})
        return httpx.Response(200, json={"message": {"role": "assistant", "content": "I cannot do that."}, "done": True})

    _install_stream([])
    assistant.set_transport(httpx.MockTransport(handler))
    out = tmp_path / "eval.json"
    code = cli.main(["eval-assistant", "--only", "scope", "--json", str(out)])
    printed = capsys.readouterr().out
    report = json.loads(out.read_text(encoding="utf-8"))
    assert report["model"] == "llama3.1:8b" and report["cases"] == 7 and "by_group" in report
    assert "scope.run_scan" in printed and "passed" in printed
    assert code == (0 if report["passed"] == report["cases"] else 1)
    assert all(r["answer"] == "I cannot do that." for r in report["results"])
