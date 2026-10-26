"""CVSS base scores (3.0 and 3.1) and plain-words explanations of every base metric.

The 3.x score follows the specification formulas exactly, including the 3.1 ``Roundup`` function
(Appendix A), which is also the mathematically correct reading of the 3.0 "round up" rule.
CVSS 4.0 vectors are explained but never scored here: a 4.0 score is used only when the source
provides one, because 4.0 scoring is a large lookup table, not a formula.
"""

from __future__ import annotations

import math
from typing import Any


class CvssError(ValueError):
    pass


BASE_METRICS_V3 = ("AV", "AC", "PR", "UI", "S", "C", "I", "A")
BASE_METRICS_V4 = ("AV", "AC", "AT", "PR", "UI", "VC", "VI", "VA", "SC", "SI", "SA")

_AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
_AC = {"L": 0.77, "H": 0.44}
_UI = {"N": 0.85, "R": 0.62}
_CIA = {"H": 0.56, "L": 0.22, "N": 0.0}
_PR = {"U": {"N": 0.85, "L": 0.62, "H": 0.27}, "C": {"N": 0.85, "L": 0.68, "H": 0.5}}


def parse_vector(vector: str) -> tuple[str, dict[str, str]]:
    """Split ``CVSS:3.1/AV:N/...`` into ("3.1", {"AV": "N", ...})."""
    if not isinstance(vector, str) or not vector.startswith("CVSS:"):
        raise CvssError(f"not a CVSS vector: {vector!r}")
    parts = vector.strip().split("/")
    version = parts[0][len("CVSS:"):]
    metrics: dict[str, str] = {}
    for part in parts[1:]:
        if not part:
            continue
        key, sep, value = part.partition(":")
        if not sep or not key or not value:
            raise CvssError(f"malformed metric {part!r} in {vector!r}")
        if key in metrics:
            raise CvssError(f"metric {key} appears twice in {vector!r}")
        metrics[key] = value
    return version, metrics


def roundup(value: float) -> float:
    """CVSS v3.1 Appendix A: the smallest one-decimal number >= value, robust to float noise."""
    int_input = round(value * 100000)
    if int_input % 10000 == 0:
        return int_input / 100000.0
    return (math.floor(int_input / 10000) + 1) / 10.0


def base_score(vector: str) -> float:
    """Base score of a CVSS 3.0 or 3.1 vector. Temporal and environmental metrics are ignored."""
    version, m = parse_vector(vector)
    if version not in ("3.0", "3.1"):
        raise CvssError(f"CVSS {version} vectors are not scored here")
    missing = [k for k in BASE_METRICS_V3 if k not in m]
    if missing:
        raise CvssError(f"vector lacks base metrics {', '.join(missing)}")
    scope = m["S"]
    if scope not in ("U", "C"):
        raise CvssError(f"invalid scope {scope!r}")
    try:
        av, ac, ui = _AV[m["AV"]], _AC[m["AC"]], _UI[m["UI"]]
        pr = _PR[scope][m["PR"]]
        c, i, a = _CIA[m["C"]], _CIA[m["I"]], _CIA[m["A"]]
    except KeyError as exc:
        raise CvssError(f"invalid metric value in {vector!r}") from exc
    iss = 1 - ((1 - c) * (1 - i) * (1 - a))
    impact = 6.42 * iss if scope == "U" else 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15
    exploitability = 8.22 * av * ac * pr * ui
    if impact <= 0:
        return 0.0
    if scope == "U":
        return roundup(min(impact + exploitability, 10))
    return roundup(min(1.08 * (impact + exploitability), 10))


def vector_version(vector: str | None) -> str | None:
    if not vector:
        return None
    try:
        return parse_vector(vector)[0]
    except CvssError:
        return None


def severity_band(score: float | None, version: str | None = "3.1") -> str | None:
    """Qualitative rating: none, low, medium, high, critical (CVSS v2 has no critical)."""
    if score is None:
        return None
    if version and version.startswith("2"):
        return "low" if score < 4.0 else "medium" if score < 7.0 else "high"
    if score <= 0:
        return "none"
    if score < 4.0:
        return "low"
    if score < 7.0:
        return "medium"
    if score < 9.0:
        return "high"
    return "critical"


def finding_severity(score: float | None, version: str | None = "3.1") -> str | None:
    """Like ``severity_band`` but in the finding vocabulary ("none" becomes "info")."""
    band = severity_band(score, version)
    return "info" if band == "none" else band


# --------------------------------------------------------------------------- explanations

_NAMES = {
    "AV": "Attack vector", "AC": "Attack complexity", "AT": "Attack requirements", "PR": "Privileges required",
    "UI": "User interaction", "S": "Scope", "C": "Confidentiality impact", "I": "Integrity impact",
    "A": "Availability impact", "VC": "Confidentiality impact on the vulnerable system",
    "VI": "Integrity impact on the vulnerable system", "VA": "Availability impact on the vulnerable system",
    "SC": "Confidentiality impact on other systems", "SI": "Integrity impact on other systems",
    "SA": "Availability impact on other systems",
}

_COMMON: dict[str, dict[str, tuple[str, str]]] = {
    "AV": {
        "N": ("Network", "Can be exploited remotely over a network, possibly from the internet."),
        "A": ("Adjacent", "The attacker must be on the same local network segment, such as the same Wi-Fi or "
                          "Bluetooth range."),
        "L": ("Local", "The attacker needs access to the device itself, or must get a user to open a malicious file."),
        "P": ("Physical", "The attacker must physically handle the device."),
    },
    "AC": {
        "L": ("Low", "No special conditions are needed; the attack works reliably."),
        "H": ("High", "Success depends on conditions the attacker does not control, such as winning a race "
                      "or knowing secret configuration."),
    },
    "PR": {
        "N": ("None", "No account or login is needed."),
        "L": ("Low", "The attacker needs an ordinary user account."),
        "H": ("High", "The attacker already needs administrator-level access."),
    },
}

_V3: dict[str, dict[str, tuple[str, str]]] = {
    **_COMMON,
    "UI": {
        "N": ("None", "No action by any user is needed."),
        "R": ("Required", "A user must do something first, such as open a file or click a link."),
    },
    "S": {
        "U": ("Unchanged", "The damage stays within the vulnerable program."),
        "C": ("Changed", "The attack can reach beyond the vulnerable program, for example escape a sandbox "
                         "or affect the operating system."),
    },
    "C": {
        "H": ("High", "The attacker can read all data the program can access, or very sensitive data."),
        "L": ("Low", "Some data can be read, but the attacker does not control which."),
        "N": ("None", "No data is exposed."),
    },
    "I": {
        "H": ("High", "The attacker can change any data or files the program can access."),
        "L": ("Low", "Some data can be changed, with limited control."),
        "N": ("None", "Nothing can be modified."),
    },
    "A": {
        "H": ("High", "The attacker can fully crash or lock up the program or device."),
        "L": ("Low", "Performance can be degraded or interrupted at times."),
        "N": ("None", "No effect on availability."),
    },
}

_V4_IMPACT = {
    "H": ("High", "Total loss in this area."),
    "L": ("Low", "Partial or limited loss in this area."),
    "N": ("None", "No impact in this area."),
}

_V4: dict[str, dict[str, tuple[str, str]]] = {
    **_COMMON,
    "AT": {
        "N": ("None", "No special deployment conditions are needed."),
        "P": ("Present", "The attack only works when specific conditions are present on the target."),
    },
    "UI": {
        "N": ("None", "No action by any user is needed."),
        "P": ("Passive", "A user must do something ordinary, such as view a page or open a file."),
        "A": ("Active", "A user must take specific, deliberate actions for the attack to work."),
    },
    **{k: _V4_IMPACT for k in ("VC", "VI", "VA", "SC", "SI", "SA")},
}


def explain(vector: str | None) -> list[dict[str, Any]]:
    """One entry per base metric: metric code and name, value code and name, and what it means."""
    if not vector:
        return []
    try:
        version, metrics = parse_vector(vector)
    except CvssError:
        return []
    table, order = (_V4, BASE_METRICS_V4) if version.startswith("4") else (_V3, BASE_METRICS_V3)
    out = []
    for key in order:
        value = metrics.get(key)
        if value is None:
            continue
        label, meaning = table.get(key, {}).get(value, (value, "Unrecognized value."))
        out.append({"metric": key, "metric_name": _NAMES.get(key, key), "value": value, "value_name": label,
                    "meaning": meaning})
    return out


def summary_sentence(vector: str | None) -> str | None:
    """A short plain-words description, e.g. 'Remotely exploitable, no login needed, no user action needed.'"""
    if not vector:
        return None
    try:
        version, m = parse_vector(vector)
    except CvssError:
        return None
    bits = []
    where = {"N": "Remotely exploitable over a network", "A": "Exploitable from the same local network",
             "L": "Needs local access or a user opening a file", "P": "Needs physical access"}.get(m.get("AV", ""))
    if where:
        bits.append(where)
    bits.append({"N": "no login needed", "L": "needs an ordinary user account",
                 "H": "needs administrator access"}.get(m.get("PR", ""), "privileges unknown"))
    ui = m.get("UI", "")
    bits.append("no user action needed" if ui == "N" else "needs a user to act" if ui else "user interaction unknown")
    if version.startswith("3"):
        highs = [name for key, name in (("C", "confidentiality"), ("I", "integrity"), ("A", "availability"))
                 if m.get(key) == "H"]
        if highs:
            bits.append("high impact on " + ", ".join(highs))
    return "; ".join(bits) + "."
