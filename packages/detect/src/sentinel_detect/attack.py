"""A tiny slice of the MITRE ATT&CK technique catalogue.

Detections reference techniques by id so that coverage can be reasoned about against a shared vocabulary
(and, later, measured: "which techniques do we actually catch?"). We keep only the handful of ids the
current rules use rather than vendoring the whole catalogue; an unknown id simply renders as itself.
"""

from __future__ import annotations

TECHNIQUES: dict[str, str] = {
    "T1059": "Command and Scripting Interpreter",
    "T1059.001": "PowerShell",
    "T1059.003": "Windows Command Shell",
    "T1059.005": "Visual Basic",
    "T1071": "Application Layer Protocol",
    "T1112": "Modify Registry",
    "T1204": "User Execution",
    "T1204.002": "Malicious File",
    "T1218": "System Binary Proxy Execution",
    "T1218.005": "Mshta",
    "T1547": "Boot or Logon Autostart Execution",
    "T1547.001": "Registry Run Keys / Startup Folder",
    "T1562": "Impair Defenses",
    "T1562.001": "Disable or Modify Tools",
    "T1566": "Phishing",
}


def names(ids: list[str]) -> list[str]:
    """Human-readable names for a list of technique ids, falling back to the id itself when unknown."""
    return [TECHNIQUES.get(i, i) for i in ids]
