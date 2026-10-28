"""A small, hand-built corpus of labelled scenarios for the measurement lab.

Each malicious scenario is a documented behaviour mapped to the rule(s) and ATT&CK technique(s) it should
trigger; each benign scenario is ordinary activity that must stay silent. This is the yardstick you grow —
adding a scenario is how you turn "I think it handles X" into a number. It is deliberately in the same spirit
as Atomic Red Team: one small, named, technique-tagged case at a time.
"""

from __future__ import annotations

from .lab import BENIGN, MALICIOUS, Scenario
from .replay import StreamBuilder

EXPLORER = r"C:\Windows\explorer.exe"
PWSH = r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
WINWORD = r"C:\Program Files\Microsoft Office\root\Office16\winword.exe"
RUNDLL = r"C:\Windows\System32\rundll32.exe"
CMD = r"C:\Windows\System32\cmd.exe"
MSBUILD = r"C:\Program Files\MSBuild\msbuild.exe"
CHROME = r"C:\Program Files\Google\Chrome\Application\chrome.exe"
SVCHOST = r"C:\Windows\System32\svchost.exe"
SERVICES = r"C:\Windows\System32\services.exe"
TEMP_EXE = r"C:\Users\sam\AppData\Local\Temp\payload.exe"
DEFENDER_RT = r"HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection"
RUN_KEY = r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"


def _macro_to_shell() -> Scenario:
    b = StreamBuilder()
    b.process_create("W", WINWORD, parent_guid="E", parent_image=EXPLORER)
    b.process_create("P", PWSH, parent_guid="W", parent_image=WINWORD, command_line="powershell -enc AAA")
    return Scenario("macro_to_shell", MALICIOUS, b.events,
                    expected_rules=frozenset({"exec.office_spawns_interpreter"}),
                    technique_ids=("T1566", "T1059"),
                    description="A Word document launches PowerShell (macro execution).")


def _exec_chain() -> Scenario:
    b = StreamBuilder()
    b.process_create("W", WINWORD, parent_guid="E", parent_image=EXPLORER)
    b.process_create("P", PWSH, parent_guid="W", parent_image=WINWORD, command_line="powershell -enc AAA")
    b.process_create("R", RUNDLL, parent_guid="P", parent_image=PWSH)
    b.network_connect("R", "45.142.212.61", 443, image=RUNDLL)
    b.registry_set("P", DEFENDER_RT, "DisableRealtimeMonitoring", value=1, image=PWSH)
    return Scenario("exec_chain", MALICIOUS, b.events,
                    expected_rules=frozenset({"intrusion.suspicious_exec_chain"}),
                    technique_ids=("T1059", "T1071", "T1562.001"),
                    description="Unusual spawn, outbound connection from a descendant, then Defender disabled.")


def _defender_disabled() -> Scenario:
    b = StreamBuilder()
    b.process_create("P", PWSH, parent_guid="E", parent_image=EXPLORER)
    b.registry_set("P", DEFENDER_RT, "DisableRealtimeMonitoring", value=1, image=PWSH)
    return Scenario("defender_disabled", MALICIOUS, b.events,
                    expected_rules=frozenset({"defense.security_tooling_disabled"}),
                    technique_ids=("T1562.001",),
                    description="A process turns off Defender real-time protection via the registry.")


def _autorun_from_temp() -> Scenario:
    b = StreamBuilder()
    b.process_create("X", TEMP_EXE, parent_guid="E", parent_image=EXPLORER)
    b.registry_set("X", RUN_KEY, "Updater", value=r"C:\Users\Public\u.exe", image=TEMP_EXE)
    return Scenario("autorun_from_temp", MALICIOUS, b.events,
                    expected_rules=frozenset({"persist.autorun_registry"}),
                    technique_ids=("T1547.001",),
                    description="A binary in a temp folder installs a Run-key autostart.")


def _admin_powershell() -> Scenario:
    b = StreamBuilder()
    b.process_create("E", EXPLORER)
    b.process_create("P", PWSH, parent_guid="E", parent_image=EXPLORER, command_line="Get-Service")
    b.network_connect("P", "10.12.0.8", 443, image=PWSH)
    b.registry_set("P", r"HKCU\Software\Contoso\Console", "LastRun", value=1, image=PWSH)
    return Scenario("admin_powershell", BENIGN, b.events,
                    description="An admin opens PowerShell from Explorer, hits an internal host, writes a user value.")


def _dev_build() -> Scenario:
    b = StreamBuilder()
    b.process_create("C", CMD, parent_guid="E", parent_image=EXPLORER)
    b.process_create("M", MSBUILD, parent_guid="C", parent_image=CMD, command_line="msbuild app.sln")
    b.network_connect("M", "10.0.0.20", 443, image=MSBUILD)  # internal package feed
    b.file_write("M", r"C:\dev\app\bin\app.dll", image=MSBUILD)
    return Scenario("dev_build", BENIGN, b.events,
                    description="A developer build: cmd -> msbuild, internal feed, writes build output.")


def _browser_download() -> Scenario:
    b = StreamBuilder()
    b.process_create("B", CHROME, parent_guid="E", parent_image=EXPLORER)
    b.network_connect("B", "140.82.113.3", 443, image=CHROME)  # a public host — egress alone is not a detection
    b.file_write("B", r"C:\Users\sam\Downloads\installer.exe", image=CHROME)
    return Scenario("browser_download", BENIGN, b.events,
                    description="A browser connects to the internet and saves a download. Egress alone must not fire.")


def _legit_autorun() -> Scenario:
    b = StreamBuilder()
    b.process_create("S", SVCHOST, parent_guid="SV", parent_image=SERVICES)
    b.registry_set("S", RUN_KEY, "WindowsUpdateHelper", value=r"C:\Windows\System32\helper.exe", image=SVCHOST)
    return Scenario("legit_autorun", BENIGN, b.events,
                    description="A system service writes a Run key — an autorun by a normal process must not fire.")


def default_corpus() -> list[Scenario]:
    return [
        _macro_to_shell(), _exec_chain(), _defender_disabled(), _autorun_from_temp(),
        _admin_powershell(), _dev_build(), _browser_download(), _legit_autorun(),
    ]
