"""Local accounts and members of the local Administrators group."""

from __future__ import annotations

from typing import Any

from sentinel_core.checks import Check, CheckContext, SkipCheck
from sentinel_core.commands import powershell
from sentinel_core.models import CheckOutput, Confidence, FindingKind, Platform, Severity

from ...safe_commands import CommandFailed
from .._util import finding, ps_list

ADMINISTRATORS_SID = "S-1-5-32-544"
MAX_ENABLED_ADMINS = 2

LOCAL_USERS = powershell(
    "ps.local_users",
    "$iso = { param($d) if ($d) { $d.ToUniversalTime().ToString('o') } }; "
    "$u = @(Get-LocalUser -ErrorAction Stop | ForEach-Object { [pscustomobject]@{"
    "Name=[string]$_.Name; Enabled=[bool]$_.Enabled; PasswordRequired=[bool]$_.PasswordRequired; "
    "PasswordLastSet=(& $iso $_.PasswordLastSet); LastLogon=(& $iso $_.LastLogon); SID=[string]$_.SID; "
    "PrincipalSource=[string]$_.PrincipalSource} }); "
    "$id = [Security.Principal.WindowsIdentity]::GetCurrent(); "
    "[pscustomobject]@{Users=$u; CurrentUser=[string]$id.Name; CurrentUserSid=[string]$id.User.Value}"
    " | ConvertTo-Json -Depth 4 -Compress",
)

# Get-LocalGroupMember throws ("Failed to compare two elements in the array" / error 1789) when the group
# holds an orphaned SID or some cloud accounts, so the script reports the error instead of failing.
ADMIN_MEMBERS = powershell(
    "ps.admin_members",
    "$r = [ordered]@{Method='Get-LocalGroupMember'}; "
    f"try {{ $r.Members = @(Get-LocalGroupMember -SID {ADMINISTRATORS_SID} -ErrorAction Stop | ForEach-Object {{ "
    "[pscustomobject]@{Name=[string]$_.Name; ObjectClass=[string]$_.ObjectClass; "
    "PrincipalSource=[string]$_.PrincipalSource; SID=[string]$_.SID} }) "
    "} catch { $r.Error = [string]$_.Exception.Message }; "
    "[pscustomobject]$r | ConvertTo-Json -Depth 4 -Compress",
)

# Fallback: CIM association first, then the ADSI WinNT provider with the group name translated from its SID
# (the group is called "Administratoren", "Administrateurs" ... on non-English Windows).
ADMIN_MEMBERS_FALLBACK = powershell(
    "ps.admin_members_fallback",
    "$r = [ordered]@{Method='CIM'}; "
    "try { $g = Get-CimInstance -ClassName Win32_Group -Filter 'LocalAccount=True' -ErrorAction Stop"
    f" | Where-Object {{ $_.SID -eq '{ADMINISTRATORS_SID}' }}; $r.GroupName = [string]$g.Name; "
    "$r.Members = @(Get-CimAssociatedInstance -InputObject $g -Association Win32_GroupUser -ErrorAction Stop"
    " | ForEach-Object { [pscustomobject]@{Name=([string]$_.Domain + '\\' + [string]$_.Name); "
    "ObjectClass=[string]$_.CimClass.CimClassName; PrincipalSource=$null; SID=[string]$_.SID} }) "
    "} catch { $r.Error = [string]$_.Exception.Message }; "
    "if ($r.Error -or -not $r.Members) { try { "
    f"$n = (New-Object System.Security.Principal.SecurityIdentifier('{ADMINISTRATORS_SID}'))"
    ".Translate([System.Security.Principal.NTAccount]).Value.Split('\\')[-1]; "
    "$grp = [ADSI]('WinNT://./' + $n + ',group'); "
    "$m = @($grp.psbase.Invoke('Members') | ForEach-Object { "
    "$t = $_.GetType(); $path = [string]$t.InvokeMember('ADsPath', 'GetProperty', $null, $_, $null); "
    "$cls = [string]$t.InvokeMember('Class', 'GetProperty', $null, $_, $null); $sid = $null; "
    "try { $sid = (New-Object System.Security.Principal.SecurityIdentifier("
    "$t.InvokeMember('objectSid', 'GetProperty', $null, $_, $null), 0)).Value } catch { }; "
    "[pscustomobject]@{Name=$path; ObjectClass=$cls; PrincipalSource=$null; SID=$sid} }); "
    "$r.Method = 'ADSI'; $r.GroupName = $n; $r.Members = $m; $r.Remove('Error') "
    "} catch { $r.AdsiError = [string]$_.Exception.Message } }; "
    "[pscustomobject]$r | ConvertTo-Json -Depth 4 -Compress",
)


def _sid_rid(sid: str | None) -> str:
    return (sid or "").rsplit("-", 1)[-1]


def _short_name(name: str) -> str:
    return name.replace("/", "\\").rsplit("\\", 1)[-1].lower()


class LocalAccounts(Check):
    id = "win.accounts"
    version = "1"
    title = "Local accounts and administrators"
    category = "configuration"
    platforms = frozenset({Platform.WINDOWS})
    timeout_seconds = 90.0
    data_collected = (
        "Names, SIDs and enabled/password-required flags of local user accounts with their last password change "
        "and last sign-in times, the members of the local Administrators group, and which account runs the agent"
    )
    commands = (LOCAL_USERS, ADMIN_MEMBERS, ADMIN_MEMBERS_FALLBACK)

    def _admins(self, ctx: CheckContext) -> tuple[list[dict[str, Any]] | None, dict[str, Any]]:
        attempts: dict[str, Any] = {}
        for spec in (ADMIN_MEMBERS, ADMIN_MEMBERS_FALLBACK):
            try:
                data = ctx.run_json(spec)
            except CommandFailed as exc:
                attempts[spec.name] = str(exc)[:300]
                continue
            if not isinstance(data, dict):
                attempts[spec.name] = "unexpected output"
                continue
            # The fallback script removes "Error" when its ADSI attempt rescues a failed CIM lookup.
            if data.get("Error") or data.get("AdsiError"):
                attempts[spec.name] = {k: data.get(k) for k in ("Method", "Error", "AdsiError") if data.get(k)}
                continue
            attempts[spec.name] = {"method": data.get("Method"), "ok": True}
            return [m for m in ps_list(data.get("Members")) if isinstance(m, dict)], attempts
        return None, attempts

    def run(self, ctx: CheckContext) -> CheckOutput:
        try:
            data = ctx.run_json(LOCAL_USERS)
        except CommandFailed as exc:
            raise SkipCheck("Local accounts could not be listed (Get-LocalUser failed)") from exc
        if not isinstance(data, dict):
            raise SkipCheck("Local accounts could not be listed (unexpected output)")
        users = [u for u in ps_list(data.get("Users")) if isinstance(u, dict)]
        current_sid = data.get("CurrentUserSid")
        admins, attempts = self._admins(ctx)

        enabled_admins: list[str] = []
        current_is_admin: bool | None = None
        if admins is not None:
            # Match on SID; fall back to the account name only when a method returned no SIDs at all.
            admin_sids = {str(m.get("SID")) for m in admins if m.get("SID")}
            admin_names = {_short_name(str(m.get("Name", ""))) for m in admins}

            def is_admin(sid: object, name: object) -> bool:
                return str(sid) in admin_sids if admin_sids else _short_name(str(name or "")) in admin_names

            enabled_admins = [str(u.get("Name")) for u in users
                              if u.get("Enabled") is True and is_admin(u.get("SID"), u.get("Name"))]
            if current_sid:
                current_is_admin = is_admin(current_sid, data.get("CurrentUser"))

        evidence = [ctx.evidence("command_output", "Get-LocalUser; Get-LocalGroupMember -SID S-1-5-32-544", {
            "users": users,
            "administrators": admins if admins is not None else "unavailable: every method of listing the "
                                                                  "Administrators group failed",
            "administrators_lookup": attempts,
            "enabled_local_administrators": enabled_admins,
            "agent_account": data.get("CurrentUser"),
            "agent_account_is_administrator": current_is_admin,
        })]
        findings = []
        for u in users:
            name, sid, enabled = str(u.get("Name")), str(u.get("SID") or ""), u.get("Enabled") is True
            rid = _sid_rid(sid)
            if enabled and rid == "501":
                findings.append(finding(
                    "win.accounts.guest_enabled", f"account:{sid}", "The Guest account is enabled",
                    Severity.HIGH,
                    "Anyone with physical or network access can sign in without a password of their own.",
                    "Open Computer Management > Local Users and Groups > Users (or run `net user guest "
                    "/active:no` in an administrator terminal yourself) and disable Guest.",
                ))
            elif enabled and rid == "500":
                findings.append(finding(
                    "win.accounts.builtin_admin_enabled", f"account:{sid}",
                    f"The built-in Administrator account ({name}) is enabled",
                    Severity.MEDIUM,
                    "Every Windows PC has this account, so attackers know its name. It is also exempt from "
                    "some User Account Control protections.",
                    "Use a named administrator account instead and disable the built-in one in Computer "
                    "Management > Local Users and Groups.",
                ))
            if enabled and u.get("PasswordRequired") is False:
                findings.append(finding(
                    "win.accounts.password_not_required", f"account:{sid}:password_required",
                    f"Account {name} is allowed to have an empty password",
                    Severity.MEDIUM,
                    "The account is flagged \"password not required\", so a blank password can be set on it and "
                    "anyone could sign in. (If you sign in to it with a Microsoft account, that sign-in still uses "
                    "the Microsoft account password.)",
                    "Make sure the account has a strong password, then clear the flag in an administrator terminal: "
                    f"`net user \"{name}\" /passwordreq:yes`.",
                ))
        if len(enabled_admins) > MAX_ENABLED_ADMINS:
            findings.append(finding(
                "win.accounts.many_admins", "administrators:count",
                f"{len(enabled_admins)} enabled local accounts are administrators",
                Severity.LOW,
                "Every administrator account is a full-control entry point; unused ones are easy to forget about.",
                "Remove administrator rights from accounts that do not need them (Settings > Accounts > Other "
                "users > Change account type).",
            ))
        if current_is_admin:
            findings.append(finding(
                "win.accounts.daily_admin", f"account:{current_sid}:daily_admin",
                f"The account used day to day ({data.get('CurrentUser')}) is a local administrator",
                Severity.INFO,
                "Programs you start can ask for full control with a single click on the UAC prompt, and some "
                "malware tricks users into approving it.",
                "Create a separate standard account for daily work and keep this administrator account for "
                "installing software and changing settings.",
                kind=FindingKind.INFORMATIONAL, confidence=Confidence.HIGH,
            ))
        return CheckOutput(evidence=evidence, findings=findings)
