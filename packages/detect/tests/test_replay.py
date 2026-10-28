"""The replay layer: stream round-tripping, the shipped samples, and the CLI."""

from __future__ import annotations

import json
from pathlib import Path

from sentinel_detect import Engine, StreamBuilder, dump_stream, load_stream, run_replay
from sentinel_detect.replay import main

SAMPLES = Path(__file__).resolve().parents[1] / "samples"


def test_dump_and_load_round_trip_preserves_events():
    b = StreamBuilder()
    b.process_create("W", r"C:\Office\winword.exe", parent_guid="E", parent_image=r"C:\explorer.exe")
    b.process_create("P", r"C:\powershell.exe", parent_guid="W", parent_image=r"C:\Office\winword.exe")
    b.network_connect("P", "8.8.8.8", 443, image=r"C:\powershell.exe")
    reloaded = load_stream_from_text(dump_stream(b.events))
    assert [e.model_dump() for e in reloaded] == [e.model_dump() for e in b.events]


def load_stream_from_text(text: str, tmp: Path | None = None) -> list:
    # small helper: load_stream reads a path, so write to a temp file first
    import tempfile
    path = Path(tempfile.mkstemp(suffix=".jsonl")[1])
    path.write_text(text, encoding="utf-8")
    return load_stream(path)


def test_load_stream_skips_comments_and_blank_lines(tmp_path: Path):
    text = (
        "# a comment\n"
        "\n"
        "// another comment\n"
        '{"kind":"process_create","ts":"2026-01-01T12:00:00Z","host":"H","seq":0,"pid":1,'
        '"process_guid":"g","image":"C:\\\\cmd.exe"}\n'
    )
    path = tmp_path / "s.jsonl"
    path.write_text(text, encoding="utf-8")
    events = load_stream(path)
    assert len(events) == 1 and events[0].process_guid == "g"


def test_shipped_suspicious_sample_fires_the_chain():
    detections = run_replay(load_stream(SAMPLES / "suspicious_chain.jsonl"))
    rule_ids = {d.rule_id for d in detections}
    assert "intrusion.suspicious_exec_chain" in rule_ids
    assert "exec.office_spawns_interpreter" in rule_ids


def test_shipped_benign_sample_is_silent():
    assert run_replay(load_stream(SAMPLES / "benign_admin.jsonl")) == []


def test_cli_text_output(capsys):
    rc = main([str(SAMPLES / "suspicious_chain.jsonl")])
    out = capsys.readouterr().out
    assert rc == 0
    assert "detection(s)" in out
    assert "suspicious execution chain" in out.lower()


def test_cli_json_output_is_valid(capsys):
    rc = main([str(SAMPLES / "suspicious_chain.jsonl"), "--json"])
    payload = json.loads(capsys.readouterr().out)
    assert rc == 0
    assert any(d["rule_id"] == "intrusion.suspicious_exec_chain" for d in payload)
    # evidence travels with each detection
    chain = next(d for d in payload if d["rule_id"] == "intrusion.suspicious_exec_chain")
    assert len(chain["events"]) == 3 and chain["process_tree"]


def test_cli_no_suppress_flag_runs(capsys):
    rc = main([str(SAMPLES / "benign_admin.jsonl"), "--no-suppress"])
    assert rc == 0
    assert "0 detection" in capsys.readouterr().out


def test_engine_default_suppression_is_on_by_default():
    # The benign sample is silent either way, but confirm the default engine wires a suppression list.
    engine = Engine()
    assert engine.suppressions is not None
