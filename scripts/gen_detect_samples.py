#!/usr/bin/env python3
"""Generate the sample telemetry streams under packages/detect/samples/.

Writing them from code (rather than by hand) keeps them valid against the event schema and easy to extend.
Run: uv run python scripts/gen_detect_samples.py
"""

from __future__ import annotations

from pathlib import Path

from sentinel_detect import StreamBuilder, dump_stream

SAMPLES = Path(__file__).resolve().parent.parent / "packages" / "detect" / "samples"

EXPLORER = r"C:\Windows\explorer.exe"
WINWORD = r"C:\Program Files\Microsoft Office\root\Office16\winword.exe"
PWSH = r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
RUNDLL = r"C:\Windows\System32\rundll32.exe"
DEFENDER_RT = r"HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection"


def suspicious_chain() -> str:
    b = StreamBuilder(host="WKS-14")
    b.process_create("gE", EXPLORER, pid=5000)
    b.process_create("gW", WINWORD, parent_guid="gE", parent_image=EXPLORER, pid=6001,
                     command_line='"winword.exe" /n "C:\\Users\\sam\\Downloads\\invoice.docm"', user="CORP\\sam")
    b.process_create("gP", PWSH, parent_guid="gW", parent_image=WINWORD, pid=6100, user="CORP\\sam",
                     command_line="powershell -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoA...")
    b.process_create("gR", RUNDLL, parent_guid="gP", parent_image=PWSH, pid=6200, user="CORP\\sam",
                     command_line="rundll32.exe C:\\Users\\Public\\u.dll,Start")
    b.network_connect("gR", "45.142.212.61", 443, image=RUNDLL)  # descendant reaches a public host
    b.registry_set("gP", DEFENDER_RT, "DisableRealtimeMonitoring", value=1, image=PWSH)  # interpreter tampers
    header = ("# Sample: a malicious execution chain.\n"
              "# Word opens a macro document, spawns PowerShell, which spawns rundll32; rundll32 connects out\n"
              "# and PowerShell disables Defender. Replay with: sentinel-detect packages/detect/samples/"
              "suspicious_chain.jsonl\n")
    return header + dump_stream(b.events)


def benign_admin() -> str:
    b = StreamBuilder(host="WKS-14")
    b.process_create("gE", EXPLORER, pid=5000)
    b.process_create("gP", PWSH, parent_guid="gE", parent_image=EXPLORER, pid=6100, user="CORP\\admin",
                     command_line="powershell -Command Get-Service")
    b.network_connect("gP", "10.12.0.8", 443, image=PWSH)  # internal update server
    b.registry_set("gP", r"HKCU\Software\Contoso\Console", "LastRun", value=1, image=PWSH)
    header = ("# Sample: an ordinary administrative session. Expected detections: none.\n"
              "# An admin opens PowerShell from Explorer, queries services, talks to an internal host, and\n"
              "# writes a benign per-user value. Nothing here should fire.\n")
    return header + dump_stream(b.events)


def main() -> None:
    SAMPLES.mkdir(parents=True, exist_ok=True)
    (SAMPLES / "suspicious_chain.jsonl").write_text(suspicious_chain(), encoding="utf-8")
    (SAMPLES / "benign_admin.jsonl").write_text(benign_admin(), encoding="utf-8")
    print(f"wrote samples to {SAMPLES}")


if __name__ == "__main__":
    main()
