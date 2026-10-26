"""CVSS 3.x base scores against the specification's reference values, bands and explanations."""

import pytest
from sentinel_server.integrations import cvss


@pytest.mark.parametrize(("vector", "score"), [
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8),
    ("CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H", 7.8),
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", 6.1),
    ("CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N", 5.9),
    # more reference values from the spec examples and NVD
    ("CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N", 5.4),
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", 10.0),
    ("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8),
    ("CVSS:3.1/AV:P/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N", 1.6),
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N", 0.0),
    ("CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H", 7.0),
    # temporal metrics are ignored for the base score
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/E:U/RL:O/RC:C", 9.8),
])
def test_base_scores(vector, score):
    assert cvss.base_score(vector) == score


def test_roundup_handles_float_noise():
    assert cvss.roundup(4.0) == 4.0
    assert cvss.roundup(4.00000000001) == 4.0  # float noise, not a real difference
    assert cvss.roundup(4.02) == 4.1
    assert cvss.roundup(9.99) == 10.0


@pytest.mark.parametrize("bad", [
    "AV:N/AC:L", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H", "CVSS:3.1/AV:X/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:Q/C:H/I:H/A:H", "CVSS:3.1/AV:N/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
])
def test_invalid_vectors_raise(bad):
    with pytest.raises(cvss.CvssError):
        cvss.base_score(bad)


def test_cvss4_is_never_scored_locally():
    v4 = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"
    with pytest.raises(cvss.CvssError):
        cvss.base_score(v4)
    assert cvss.vector_version(v4) == "4.0"
    explained = {e["metric"]: e for e in cvss.explain(v4)}
    assert explained["AT"]["value_name"] == "None"
    assert explained["VC"]["metric_name"] == "Confidentiality impact on the vulnerable system"


@pytest.mark.parametrize(("score", "band"), [
    (0.0, "none"), (0.1, "low"), (3.9, "low"), (4.0, "medium"), (6.9, "medium"), (7.0, "high"),
    (8.9, "high"), (9.0, "critical"), (10.0, "critical"), (None, None),
])
def test_severity_bands(score, band):
    assert cvss.severity_band(score) == band


def test_v2_has_no_critical_band_and_finding_vocabulary():
    assert cvss.severity_band(10.0, "2.0") == "high"
    assert cvss.finding_severity(0.0) == "info"
    assert cvss.finding_severity(9.8) == "critical"


def test_plain_words_explanation():
    items = cvss.explain("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N")
    assert [i["metric"] for i in items] == ["AV", "AC", "PR", "UI", "S", "C", "I", "A"]
    av = items[0]
    assert av["value_name"] == "Network" and "remotely" in av["meaning"]
    assert items[4]["value_name"] == "Changed"
    sentence = cvss.summary_sentence("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
    assert sentence == ("Remotely exploitable over a network; no login needed; no user action needed; "
                        "high impact on confidentiality, integrity, availability.")
    assert cvss.explain(None) == [] and cvss.explain("garbage") == []
