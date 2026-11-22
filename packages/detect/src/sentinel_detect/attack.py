"""A tiny slice of the MITRE ATT&CK technique catalogue.

Detections reference techniques by id so that coverage can be reasoned about against a shared vocabulary
(and, later, measured: "which techniques do we actually catch?"). We keep only the handful of ids the
current rules use rather than vendoring the whole catalogue; an unknown id simply renders as itself.
"""

from __future__ import annotations

TECHNIQUES: dict[str, str] = {
    "T1003": "OS Credential Dumping",
    "T1003.001": "LSASS Memory",
    "T1053": "Scheduled Task/Job",
    "T1053.005": "Scheduled Task",
    "T1055": "Process Injection",
    "T1059": "Command and Scripting Interpreter",
    "T1059.001": "PowerShell",
    "T1059.003": "Windows Command Shell",
    "T1059.005": "Visual Basic",
    "T1071": "Application Layer Protocol",
    "T1105": "Ingress Tool Transfer",
    "T1112": "Modify Registry",
    "T1140": "Deobfuscate/Decode Files or Information",
    "T1197": "BITS Jobs",
    "T1204": "User Execution",
    "T1204.002": "Malicious File",
    "T1218": "System Binary Proxy Execution",
    "T1218.005": "Mshta",
    "T1218.010": "Regsvr32",
    "T1218.011": "Rundll32",
    "T1486": "Data Encrypted for Impact",
    "T1490": "Inhibit System Recovery",
    "T1546": "Event Triggered Execution",
    "T1546.003": "Windows Management Instrumentation Event Subscription",
    "T1547": "Boot or Logon Autostart Execution",
    "T1547.001": "Registry Run Keys / Startup Folder",
    "T1562": "Impair Defenses",
    "T1562.001": "Disable or Modify Tools",
    "T1566": "Phishing",
}


def names(ids: list[str]) -> list[str]:
    """Human-readable names for a list of technique ids, falling back to the id itself when unknown."""
    return [TECHNIQUES.get(i, i) for i in ids]
