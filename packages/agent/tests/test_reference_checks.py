"""Reference checks against fixture data shaped like real command output (not recordings)."""

import time

from sentinel_agent.checks.common.resources import ResourceDiagnostics
from sentinel_agent.checks.windows.firewall import FIREWALL_PROFILES, FirewallProfiles
from sentinel_agent.checks.windows.uac import UAC_KEY, UacConfiguration
from sentinel_agent.testing import FixtureContext, linux_host, ps_json, reg, windows_host
from sentinel_core.models import Severity


def test_firewall_flags_disabled_public_profile():
    fixture = {"commands": {FIREWALL_PROFILES.name: ps_json([
        {"Name": "Domain", "Enabled": "True", "DefaultInboundAction": "NotConfigured"},
        {"Name": "Private", "Enabled": "True", "DefaultInboundAction": "NotConfigured"},
        {"Name": "Public", "Enabled": "False", "DefaultInboundAction": "NotConfigured"},
    ])}}
    out = FirewallProfiles().run(FixtureContext(windows_host(), fixture))
    assert [f.rule_id for f in out.findings] == ["win.firewall.profile_disabled"]
    assert out.findings[0].severity is Severity.HIGH
    assert out.findings[0].subject_key == "firewall:Public"


def test_firewall_single_profile_object_is_handled():
    fixture = {"commands": {FIREWALL_PROFILES.name: ps_json({"Name": "Private", "Enabled": "True"})}}
    assert FirewallProfiles().run(FixtureContext(windows_host(), fixture)).findings == []


def test_uac_disabled_is_high():
    fixture = {"registry": {
        reg("HKLM", UAC_KEY, "EnableLUA", "64"): 0,
        reg("HKLM", UAC_KEY, "ConsentPromptBehaviorAdmin", "64"): 5,
        reg("HKLM", UAC_KEY, "PromptOnSecureDesktop", "64"): 1,
    }}
    out = UacConfiguration().run(FixtureContext(windows_host(), fixture))
    assert [f.rule_id for f in out.findings] == ["win.uac.disabled"]


def test_uac_default_settings_pass():
    fixture = {"registry": {
        reg("HKLM", UAC_KEY, "EnableLUA", "64"): 1,
        reg("HKLM", UAC_KEY, "ConsentPromptBehaviorAdmin", "64"): 5,
        reg("HKLM", UAC_KEY, "PromptOnSecureDesktop", "64"): 1,
    }}
    assert UacConfiguration().run(FixtureContext(windows_host(), fixture)).findings == []


def test_resources_flags_low_disk_and_long_uptime():
    fixture = {"system": {
        "cpu_percent": 12.0,
        "memory": {"total": 16e9, "available": 8e9, "percent": 50.0},
        "disks": [{"mountpoint": "/", "fstype": "ext4", "total": 100, "used": 95, "free": 5, "percent": 95.0}],
        "boot_time": time.time() - 45 * 86400,
    }}
    out = ResourceDiagnostics().run(FixtureContext(linux_host(), fixture))
    assert {f.rule_id for f in out.findings} == {"diag.disk_low_space", "diag.long_uptime"}
    assert any(m.metric == "memory_percent" for m in out.metrics)
