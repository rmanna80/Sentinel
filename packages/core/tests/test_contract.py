import pytest
from sentinel_core.commands import CommandParamError, CommandSpec, ParamKind, powershell, validate_target
from sentinel_core.fingerprint import fingerprint
from sentinel_core.redaction import redact


def test_int_params_can_be_embedded_and_are_validated():
    spec = CommandSpec("t.events", "powershell", ("-Command", "Get-WinEvent -FilterXPath '*[System[EventRecordID>{cursor}]]'"),
                       params={"cursor": ParamKind.INT})
    assert spec.render({"cursor": 42})[1].endswith("EventRecordID>42]]'")
    for bad in (-1, "42", True, 4.2):
        with pytest.raises(CommandParamError):
            spec.render({"cursor": bad})


def test_string_params_must_be_whole_arguments():
    with pytest.raises(ValueError):
        CommandSpec("t.bad", "nmap", ("--host={target}",), params={"target": ParamKind.TARGET})


def test_undeclared_and_unused_placeholders_are_rejected():
    with pytest.raises(ValueError):
        CommandSpec("t.undeclared", "ss", ("{port}",))
    with pytest.raises(ValueError):
        CommandSpec("t.unused", "ss", ("-tln",), params={"x": ParamKind.INT})


def test_missing_or_extra_params_are_rejected():
    spec = CommandSpec("t.nmap", "nmap", ("-sT", "{target}"), params={"target": ParamKind.TARGET})
    with pytest.raises(CommandParamError):
        spec.render({})
    with pytest.raises(CommandParamError):
        spec.render({"target": "10.0.0.1", "extra": 1})


@pytest.mark.parametrize("value", ["-sS", "--script=evil", "10.0.0.1; rm -rf /", "a b", "$(whoami)", "x" * 300])
def test_targets_reject_option_and_shell_injection(value):
    spec = CommandSpec("t.nmap", "nmap", ("-sT", "{target}"), params={"target": ParamKind.TARGET})
    with pytest.raises(CommandParamError):
        spec.render({"target": value})


def test_targets_accept_ips_cidrs_and_hostnames():
    assert validate_target("192.168.1.0/24") == "192.168.1.0/24"
    assert validate_target("192.168.1.7/24") == "192.168.1.0/24"
    assert validate_target("fe80::1") == "fe80::1"
    assert validate_target("Pi5.local.") == "pi5.local"


def test_powershell_spec_forces_utf8_and_fixed_flags():
    spec = powershell("t.ps", "Get-Date | ConvertTo-Json")
    args = spec.render()
    assert args[:3] == ["-NoProfile", "-NonInteractive", "-Command"]
    assert "UTF8" in args[3] and args[3].endswith("Get-Date | ConvertTo-Json")


def test_fingerprint_is_stable_and_scoped():
    a = fingerprint("win.firewall.profile_disabled", 1, "firewall:Public")
    assert a == fingerprint("win.firewall.profile_disabled", 1, "FIREWALL:public ")
    assert a != fingerprint("win.firewall.profile_disabled", 2, "firewall:Public")
    assert a != fingerprint("win.firewall.profile_disabled", 1, "firewall:Public", scope="10.0.0.5")


def test_redaction_strips_secrets_recursively():
    value, changed = redact({"api_key": "abc123", "nested": ["password=hunter2", "fine"], "PasswordRequired": True})
    assert changed
    assert value["api_key"] == "[REDACTED]"
    assert value["nested"][0] == "password=[REDACTED]"
    assert value["PasswordRequired"] is True
