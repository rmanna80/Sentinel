"""The measurement lab: the corpus scores clean, and the scorer counts FP/FN correctly."""

from __future__ import annotations

from sentinel_detect import StreamBuilder, default_corpus, measure_throughput, score
from sentinel_detect.corpus import _macro_to_shell
from sentinel_detect.lab import BENIGN, MALICIOUS, Scenario


def test_corpus_scores_perfectly():
    card = score(default_corpus())
    assert card.precision == 1.0 and card.recall == 1.0
    assert card.fp == 0 and card.fn == 0
    assert card.tp == 4 and card.tn == 4
    # every malicious scenario fired exactly the rule it was supposed to
    for r in card.results:
        if r.label == MALICIOUS:
            assert r.detected and not r.missing_rules
        else:
            assert not r.unexpected_rules


def test_all_corpus_techniques_are_covered():
    card = score(default_corpus())
    assert card.technique_coverage  # non-empty
    assert all(card.technique_coverage.values())


def test_latency_is_measured_for_detections():
    card = score(default_corpus())
    stats = card.latency_stats()
    assert stats["count"] == 4  # one per malicious scenario
    assert stats["min"] >= 0 and stats["max"] >= stats["min"]


def test_a_missed_malicious_scenario_counts_as_a_false_negative():
    # Expect a rule that cannot fire on this stream -> the scenario is "missed".
    b = StreamBuilder()
    b.process_create("E", r"C:\Windows\explorer.exe")
    b.process_create("P", r"C:\Windows\System32\notepad.exe", parent_guid="E", parent_image=r"C:\Windows\explorer.exe")
    sc = Scenario("impossible", MALICIOUS, b.events, expected_rules=frozenset({"exec.office_spawns_interpreter"}),
                  technique_ids=("T1566",))
    card = score([sc])
    assert card.fn == 1 and card.tp == 0 and card.recall == 0.0
    assert card.technique_coverage == {"T1566": False}


def test_a_benign_scenario_that_fires_counts_as_a_false_positive():
    # Mislabel the macro scenario as benign: the engine still (correctly) fires, which the lab scores as a FP.
    macro = _macro_to_shell()
    mislabelled = Scenario(macro.name, BENIGN, macro.events)
    card = score([mislabelled])
    assert card.fp == 1 and card.tn == 0 and card.precision == 0.0
    assert card.results[0].unexpected_rules


def test_throughput_benchmark_runs():
    perf = measure_throughput(500)
    assert perf["events"] == 500
    assert perf["events_per_second"] > 0
    assert perf["process_tree_size"] > 0
