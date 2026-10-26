"""CPU, memory, disk and uptime diagnostics."""

from __future__ import annotations

import time

from sentinel_core.checks import Check, CheckContext
from sentinel_core.models import CheckOutput, MetricSample, Platform, Severity, utcnow

from .._util import finding

LOW_DISK_PERCENT_FREE = 10.0
LONG_UPTIME_DAYS = 30


class ResourceDiagnostics(Check):
    id = "diag.resources"
    version = "1"
    title = "System resources and uptime"
    category = "diagnostics"
    platforms = frozenset({Platform.WINDOWS, Platform.LINUX})
    profiles = frozenset({"posture"})
    data_collected = "CPU and memory use, disk space per drive, and time since last boot"

    def run(self, ctx: CheckContext) -> CheckOutput:
        cpu = ctx.system.cpu_percent()
        mem = ctx.system.memory()
        disks = ctx.system.disks()
        boot = ctx.system.boot_time()
        uptime_days = (time.time() - boot) / 86400 if boot else None
        evidence = [ctx.evidence("metric", "psutil", {
            "cpu_percent": cpu, "memory": mem, "disks": disks,
            "uptime_days": round(uptime_days, 2) if uptime_days is not None else None,
        })]
        now = utcnow()
        metrics = [MetricSample(metric="cpu_percent", value=cpu, ts=now),
                   MetricSample(metric="memory_percent", value=float(mem.get("percent", 0)), ts=now)]
        findings = []
        for d in disks:
            if not d.get("total"):
                continue
            free_pct = 100.0 * d["free"] / d["total"]
            metrics.append(MetricSample(metric=f"disk_percent:{d['mountpoint']}", value=float(d["percent"]), ts=now))
            system_drive = d["mountpoint"] in ("C:\\", "/")
            if system_drive and free_pct < LOW_DISK_PERCENT_FREE:
                findings.append(finding(
                    "diag.disk_low_space", f"disk:{d['mountpoint']}",
                    f"Only {free_pct:.0f}% free on {d['mountpoint']}",
                    Severity.LOW,
                    "Updates, logs and antivirus definitions can fail to install when the system drive is nearly full.",
                    "Free space with Storage Sense or Disk Cleanup (Windows), or remove unused packages and logs (Linux).",
                    category="diagnostics",
                ))
        if uptime_days is not None and uptime_days > LONG_UPTIME_DAYS:
            findings.append(finding(
                "diag.long_uptime", "uptime",
                f"No restart in {uptime_days:.0f} days",
                Severity.LOW,
                "Many security updates only take effect after a restart.",
                "Restart the machine, then re-run this check.",
                category="diagnostics",
            ))
        return CheckOutput(evidence=evidence, findings=findings, metrics=metrics)
