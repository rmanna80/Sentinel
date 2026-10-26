"""Windows Update history and service state."""

from __future__ import annotations

from datetime import timedelta

from sentinel_core.checks import Check, CheckContext, SkipCheck
from sentinel_core.commands import powershell
from sentinel_core.models import CheckOutput, Confidence, FindingKind, Platform, Severity, utcnow

from ...safe_commands import CommandFailed, as_list
from .._util import finding, ok_int, parse_iso

STALE_AFTER_DAYS = 35
RESULT_SUCCEEDED = 2
OPERATION_INSTALL = 1
OPERATIONS = {1: "Installation", 2: "Uninstallation"}
RESULT_CODES = {0: "Not started", 1: "In progress", 2: "Succeeded", 3: "Succeeded with errors", 4: "Failed", 5: "Aborted"}
# Defender intelligence updates arrive through Windows Update several times a day. They say nothing about
# whether the operating system itself is patched, so they are listed in evidence but not counted.
_NOT_OS_PATCHES = ("security intelligence update", "definition update")

# WUA returns history dates in UTC with an unspecified kind, so the script marks them as UTC instead of converting.
UPDATE_HISTORY = powershell(
    "ps.windows_update_history",
    "$r = [ordered]@{CollectedAt = (Get-Date).ToUniversalTime().ToString('o')}; "
    "try { "
    "$q = (New-Object -ComObject Microsoft.Update.Session).CreateUpdateSearcher(); "
    "$n = $q.GetTotalHistoryCount(); $r.TotalCount = $n; "
    "$r.History = @(if ($n -gt 0) { $q.QueryHistory(0, [Math]::Min($n, 100)) | ForEach-Object { "
    "[pscustomobject]@{Title=[string]$_.Title; Date=[DateTime]::SpecifyKind($_.Date, 'Utc').ToString('o'); "
    "ResultCode=[int]$_.ResultCode; Operation=[int]$_.Operation} } }) "
    "} catch { $r.HistoryError = [string]$_.Exception.Message }; "
    "try { $s = Get-Service -Name wuauserv -ErrorAction Stop; "
    "$r.WuauservStartType = [string]$s.StartType; $r.WuauservStatus = [string]$s.Status "
    "} catch { $r.ServiceError = [string]$_.Exception.Message }; "
    "[pscustomobject]$r | ConvertTo-Json -Depth 4 -Compress",
    timeout=90,
)


class WindowsUpdates(Check):
    id = "win.os.updates"
    version = "1"
    title = "Windows updates are being installed"
    category = "configuration"
    platforms = frozenset({Platform.WINDOWS})
    timeout_seconds = 120.0
    data_collected = (
        "The last 100 entries of the Windows Update history (update title, date, result and whether it was an "
        "install or uninstall) and the start type of the Windows Update service"
    )
    commands = (UPDATE_HISTORY,)

    def run(self, ctx: CheckContext) -> CheckOutput:
        try:
            data = ctx.run_json(UPDATE_HISTORY)
        except CommandFailed as exc:
            raise SkipCheck(f"Windows Update history could not be read: {exc}") from exc
        if not isinstance(data, dict):
            raise SkipCheck("Windows Update history could not be read (unexpected output)")
        history = [h for h in as_list(data.get("History")) if isinstance(h, dict)]
        start_type = data.get("WuauservStartType")
        now = parse_iso(data.get("CollectedAt")) or utcnow()

        last_install = None
        counted = 0
        for h in history:
            title = str(h.get("Title") or "").lower()
            if any(marker in title for marker in _NOT_OS_PATCHES):
                continue
            counted += 1
            when = parse_iso(h.get("Date"))
            if h.get("ResultCode") == RESULT_SUCCEEDED and h.get("Operation") == OPERATION_INSTALL and when:
                last_install = max(last_install, when) if last_install else when

        evidence = [ctx.evidence("command_output", "Microsoft.Update.Session QueryHistory; Get-Service wuauserv", {
            "collected_at": data.get("CollectedAt"),
            "total_history_count": data.get("TotalCount"),
            "history_error": data.get("HistoryError"),
            "wuauserv_start_type": start_type,
            "wuauserv_status": data.get("WuauservStatus"),
            "service_error": data.get("ServiceError"),
            "last_successful_install": last_install.isoformat() if last_install else None,
            "entries_counted_as_os_updates": counted,
            "note": "Microsoft Defender security intelligence updates are listed but not counted as OS updates.",
            "history": [
                {**h, "Result": RESULT_CODES.get(ok_int(h.get("ResultCode"), -1), h.get("ResultCode")),
                 "Operation": OPERATIONS.get(ok_int(h.get("Operation"), -1), h.get("Operation"))}
                for h in history
            ],
        })]
        findings = []
        if str(start_type) == "Disabled":
            findings.append(finding(
                "win.os.updates.service_disabled", "wuauserv:start_type",
                "The Windows Update service is disabled",
                Severity.HIGH,
                "Windows cannot download or install security updates while the service is disabled.",
                "Open Services (services.msc), set Windows Update to Manual, start it, then run Settings > "
                "Windows Update > Check for updates. If a tool disabled it on purpose, remove that tool's setting.",
            ))
        if data.get("HistoryError"):
            if not findings:
                raise SkipCheck(f"Windows Update history could not be read: {str(data['HistoryError'])[:200]}")
        elif last_install is None or now - last_install > timedelta(days=STALE_AFTER_DAYS):
            when_text = f"since {last_install.date().isoformat()}" if last_install else "in the update history"
            findings.append(finding(
                "win.os.updates.stale", "windows_update:last_install",
                f"No Windows update installed successfully {when_text}",
                Severity.MEDIUM,
                f"Windows normally installs security updates every month. Nothing succeeded in the last "
                f"{STALE_AFTER_DAYS} days, so recently fixed vulnerabilities may still be open on this machine.",
                "Open Settings > Windows Update, select Check for updates and install everything offered, then "
                "restart. If installs keep failing, look at Update history for the error code.",
            ))
        if ctx.host.is_insider_build:
            findings.append(finding(
                "win.os.updates.insider_build", "windows:insider",
                "Insider build: Microsoft's monthly security guide does not map to this build",
                Severity.INFO,
                "Insider Preview builds receive fixes through new flights rather than the monthly cumulative "
                "updates, so published security bulletins cannot be matched to this build number.",
                "Keep taking new Insider flights promptly, or leave the Insider Program for a release build if you "
                "want security bulletins to apply directly.",
                kind=FindingKind.INFORMATIONAL, confidence=Confidence.HIGH,
            ))
        return CheckOutput(evidence=evidence, findings=findings)
