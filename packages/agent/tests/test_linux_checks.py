"""Linux checks against hand-written fixtures shaped like Debian/Ubuntu/Raspberry Pi OS output (not recordings)."""

import json

import pytest
from sentinel_agent.checks.linux import authlog as al
from sentinel_agent.checks.linux import packages as pk
from sentinel_agent.checks.linux import ssh
from sentinel_agent.checks.linux import system as sysc
from sentinel_agent.checks.linux import updates as up
from sentinel_agent.config import MemoryState
from sentinel_agent.testing import FixtureContext, linux_host
from sentinel_core.checks import NotApplicable, SkipCheck
from sentinel_core.commands import _PLACEHOLDER_RE, CommandSpec
from sentinel_core.models import Severity

PI = linux_host()
UBUNTU = linux_host(hostname="ubuntu-box", os_name="Ubuntu 24.04.3 LTS", os_version="24.04", distro_id="ubuntu",
                    distro_version="24.04", os_build="6.8.0-85-generic", arch="x86_64")
APT_WARNING = "\nWARNING: apt does not have a stable CLI interface. Use with caution in scripts.\n\n"


def rules(out):
    return sorted(f.rule_id for f in out.findings)


# --------------------------------------------------------------------------- linux.updates

APT_OUT = """Listing...
libssl3/stable-security 3.0.17-1~deb12u2 arm64 [upgradable from: 3.0.15-1~deb12u1]
openssl/stable-security 3.0.17-1~deb12u2 arm64 [upgradable from: 3.0.15-1~deb12u1]
raspi-firmware/stable 1:1.20250430-4~bookworm arm64 [upgradable from: 1:1.20250305-1~bookworm]
curl/stable 7.88.1-10+deb12u14 arm64 [upgradable from: 7.88.1-10+deb12u12]
"""


def _apt(stdout, files=None):
    return {"commands": {up.APT_UPGRADABLE.name: {"stdout": stdout, "stderr": APT_WARNING}}, "files": files or {}}


def test_updates_security_pending_and_restart_required():
    files = {up.REBOOT_REQUIRED: "*** System restart required ***\n", up.REBOOT_PKGS: "linux-image-6.6.74\nlibc6\n"}
    out = up.LinuxUpdates().run(FixtureContext(PI, _apt(APT_OUT, files)))
    by = {f.rule_id: f for f in out.findings}
    assert set(by) == {"linux.updates.security_pending", "linux.updates.restart_required"}
    assert by["linux.updates.security_pending"].severity is Severity.MEDIUM
    assert "2 security updates" in by["linux.updates.security_pending"].title
    assert out.evidence[0].content["reboot_required_packages"] == ["libc6", "linux-image-6.6.74"]
    assert out.evidence[0].content["other_updates"] == 2


def test_updates_many_security_updates_is_high_and_ubuntu_multi_suite():
    lines = ["Listing... Done"] + [
        f"pkg{i}/noble-updates,noble-security 1.{i}-0ubuntu0.24.04.1 amd64 [upgradable from: 1.{i}-0ubuntu0.24.04.0]"
        for i in range(21)]
    out = up.LinuxUpdates().run(FixtureContext(UBUNTU, _apt("\n".join(lines) + "\n")))
    assert rules(out) == ["linux.updates.security_pending"] and out.findings[0].severity is Severity.HIGH


def test_updates_only_regular_updates_is_low_and_none_passes():
    out = up.LinuxUpdates().run(FixtureContext(PI, _apt("Listing...\ncurl/stable 7.88.1-10+deb12u14 arm64 "
                                                        "[upgradable from: 7.88.1-10+deb12u12]\n")))
    assert rules(out) == ["linux.updates.pending"] and out.findings[0].severity is Severity.LOW
    assert up.LinuxUpdates().run(FixtureContext(PI, _apt("Listing...\n"))).findings == []


def test_updates_without_apt_skips():
    fixture = {"commands": {up.APT_UPGRADABLE.name: {"error": "not_found", "message": "apt is not installed"}}}
    with pytest.raises(SkipCheck, match="APT is not installed"):
        up.LinuxUpdates().run(FixtureContext(PI, fixture))


# --------------------------------------------------------------------------- linux.unattended_upgrades


def _aptconf(files):
    out = {up.APT_CONF_DIR + "::<listdir>": "\n".join(sorted(files))}
    out.update({f"{up.APT_CONF_DIR}/{k}": v for k, v in files.items()})
    return {"files": out}


def test_unattended_upgrades_enabled_passes():
    files = {"20auto-upgrades": 'APT::Periodic::Update-Package-Lists "1";\nAPT::Periodic::Unattended-Upgrade "1";\n',
             "50unattended-upgrades": "Unattended-Upgrade::Origins-Pattern {};\n"}
    out = up.UnattendedUpgrades().run(FixtureContext(PI, _aptconf(files)))
    assert out.findings == [] and out.evidence[0].content["set_in"] == "20auto-upgrades"


def test_unattended_upgrades_missing_or_overridden_is_low():
    out = up.UnattendedUpgrades().run(FixtureContext(PI, _aptconf({"70debconf": "// nothing\n"})))
    assert rules(out) == ["linux.unattended_upgrades.off"]
    files = {"20auto-upgrades": 'APT::Periodic::Unattended-Upgrade "1";\n',
             "99local": 'APT::Periodic::Unattended-Upgrade "0";\n'}
    assert rules(up.UnattendedUpgrades().run(FixtureContext(PI, _aptconf(files)))) == ["linux.unattended_upgrades.off"]


def test_unattended_upgrades_read_errors_never_pass():
    with pytest.raises(NotApplicable, match="APT is not used"):
        up.UnattendedUpgrades().run(FixtureContext(PI, {}))
    with pytest.raises(SkipCheck, match=r"apt\.conf\.d could not be read"):
        up.UnattendedUpgrades().run(FixtureContext(PI, {"files": {up.APT_CONF_DIR + "::<listdir>": None}}))
    files = _aptconf({"20auto-upgrades": 'APT::Periodic::Unattended-Upgrade "1";\n', "99local": "x"})
    files["files"][f"{up.APT_CONF_DIR}/99local"] = None  # may override the setting
    with pytest.raises(SkipCheck, match="99local could not be read"):
        up.UnattendedUpgrades().run(FixtureContext(PI, files))


# --------------------------------------------------------------------------- linux.ssh_config

DEBIAN_SSHD = """# This is the sshd server system-wide configuration file.
Include /etc/ssh/sshd_config.d/*.conf

#PermitRootLogin prohibit-password
#PasswordAuthentication yes
KbdInteractiveAuthentication no
UsePAM yes
X11Forwarding yes
PrintMotd no
AcceptEnv LANG LC_*
Subsystem\tsftp\t/usr/lib/openssh/sftp-server
"""


def _sshd(main, dropins=None):
    files = {ssh.SSHD_CONFIG: main, ssh.DROPIN_DIR + "::<listdir>": "\n".join(sorted(dropins or {}))}
    files.update({f"{ssh.DROPIN_DIR}/{k}": v for k, v in (dropins or {}).items()})
    return {"files": files}


def test_ssh_default_debian_config_flags_password_auth_default():
    out = ssh.SshServerConfig().run(FixtureContext(PI, _sshd(DEBIAN_SSHD)))
    assert rules(out) == ["linux.ssh_config.password_auth"]
    assert "default is yes" in out.findings[0].title and out.findings[0].severity is Severity.MEDIUM
    assert "passwordauthentication" in out.evidence[0].content["defaults_assumed"]


def test_ssh_dropin_wins_over_main_file():
    main = DEBIAN_SSHD + "PasswordAuthentication yes\nPermitRootLogin yes\n"
    dropins = {"10-hardening.conf": "PasswordAuthentication no\nPermitRootLogin no\n", "README": "x"}
    out = ssh.SshServerConfig().run(FixtureContext(PI, _sshd(main, dropins)))
    assert out.findings == []
    assert out.evidence[0].content["set_in"]["passwordauthentication"].endswith("10-hardening.conf")


def test_ssh_root_login_and_first_value_wins_and_match_ignored():
    main = ("PermitRootLogin yes\nPermitRootLogin no\nPasswordAuthentication no\n"
            "Match User backup\n    PasswordAuthentication yes\n")
    out = ssh.SshServerConfig().run(FixtureContext(PI, _sshd(main)))
    assert rules(out) == ["linux.ssh_config.root_login"] and out.findings[0].severity is Severity.HIGH


def test_ssh_missing_dropin_folder_means_no_dropins():
    out = ssh.SshServerConfig().run(FixtureContext(PI, {"files": {ssh.SSHD_CONFIG: DEBIAN_SSHD}}))
    assert rules(out) == ["linux.ssh_config.password_auth"]
    assert out.evidence[0].content["dropins_present"] == [] and out.evidence[0].content["unreadable"] == []


def test_ssh_unreadable_dropin_skips_instead_of_passing():
    # The main file alone would pass; a root-only drop-in (like cloud-init's) may turn passwords back on.
    main = DEBIAN_SSHD + "PasswordAuthentication no\n"
    fixture = _sshd(main, {"50-cloud-init.conf": "x"})
    fixture["files"][f"{ssh.DROPIN_DIR}/50-cloud-init.conf"] = None
    with pytest.raises(SkipCheck, match=r"50-cloud-init\.conf"):
        ssh.SshServerConfig().run(FixtureContext(PI, fixture))
    unreadable_dir = {"files": {ssh.SSHD_CONFIG: main, ssh.DROPIN_DIR + "::<listdir>": None}}
    with pytest.raises(SkipCheck, match="elevated scan"):
        ssh.SshServerConfig().run(FixtureContext(PI, unreadable_dir))


def test_ssh_not_installed_is_not_applicable():
    with pytest.raises(NotApplicable, match="OpenSSH server not installed"):
        ssh.SshServerConfig().run(FixtureContext(PI, {}))


# --------------------------------------------------------------------------- linux.firewall

ROOT_PI = linux_host(is_elevated=True)


def test_firewall_ufw_active_passes_and_inactive_is_medium():
    active = {"commands": {sysc.UFW_STATUS.name: {"stdout": "Status: active\n\nTo   Action  From\n22/tcp ALLOW Anywhere\n"}}}
    assert sysc.LinuxFirewall().run(FixtureContext(ROOT_PI, active)).findings == []
    inactive = {"commands": {sysc.UFW_STATUS.name: {"stdout": "Status: inactive\n"}}}
    out = sysc.LinuxFirewall().run(FixtureContext(ROOT_PI, inactive))
    assert rules(out) == ["linux.firewall.inactive"] and out.findings[0].severity is Severity.MEDIUM


NFT_RULES = """table inet filter {
\tchain input {
\t\ttype filter hook input priority filter; policy drop;
\t\tct state established,related accept
\t\ttcp dport 22 accept
\t}
}
"""


def test_firewall_falls_back_to_nft_when_ufw_missing():
    missing = {"error": "not_found", "message": "ufw is not installed"}
    configured = {"commands": {sysc.UFW_STATUS.name: missing, sysc.NFT_RULESET.name: {"stdout": NFT_RULES}}}
    out = sysc.LinuxFirewall().run(FixtureContext(ROOT_PI, configured))
    assert out.findings == [] and out.evidence[0].content["nft_tables"] == ["inet filter"]
    empty = {"commands": {sysc.UFW_STATUS.name: missing, sysc.NFT_RULESET.name: {"stdout": ""}}}
    assert rules(sysc.LinuxFirewall().run(FixtureContext(ROOT_PI, empty))) == ["linux.firewall.inactive"]


def test_firewall_no_tools_skips():
    missing = {"error": "not_found", "message": "not installed"}
    with pytest.raises(SkipCheck):
        sysc.LinuxFirewall().run(FixtureContext(ROOT_PI, {"commands": {sysc.UFW_STATUS.name: missing,
                                                                       sysc.NFT_RULESET.name: missing}}))


# --------------------------------------------------------------------------- linux.accounts

PASSWD = """root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
sshd:x:105:65534::/run/sshd:/usr/sbin/nologin
pi:x:1000:1000:,,,:/home/pi:/bin/bash
"""


def test_accounts_only_root_uid0_passes():
    out = sysc.LinuxAccounts().run(FixtureContext(PI, {"files": {"/etc/passwd": PASSWD}}))
    assert out.findings == []
    assert [a["name"] for a in out.evidence[0].content["login_shell_accounts"]] == ["root", "pi"]


def test_accounts_extra_uid0_is_high():
    text = PASSWD + "toor:x:0:0::/root:/bin/sh\n"
    out = sysc.LinuxAccounts().run(FixtureContext(PI, {"files": {"/etc/passwd": text}}))
    assert rules(out) == ["linux.accounts.extra_uid0"] and out.findings[0].subject_key == "account:toor"


# --------------------------------------------------------------------------- linux.packages


def test_package_format_strings_do_not_trip_placeholder_detection():
    assert _PLACEHOLDER_RE.findall(pk.DPKG_FORMAT) == [] and _PLACEHOLDER_RE.findall(pk.RPM_FORMAT) == []
    assert pk.DPKG_QUERY.render() == [
        "-W", "-f=${Package}\\t${Version}\\t${db:Status-Abbrev}\\t${source:Package}\\t${source:Version}\\n"]
    assert pk.RPM_QUERY.render() == ["-qa", "--qf", "%{NAME}\\t%{EPOCHNUM}:%{VERSION}-%{RELEASE}\\n"]
    CommandSpec("probe", "dpkg-query", ("-W", pk.DPKG_FORMAT))  # constructing again must not raise
    assert pk.DPKG_QUERY.params == {} and pk.RPM_QUERY.params == {}


DPKG = ("adduser\t3.134\tii \nbash\t5.2.15-2+b7\tii \nopenssl\t3.0.15-1~deb12u1\tii \nlibssl3\t3.0.15-1~deb12u1\tii \n"
        "raspi-firmware\t1:1.20250305-1~bookworm\tii \nrpi-eeprom\t26.3-1\tii \nlibcamera0.5\t0.5.0+rpt20250429-1\tii \n"
        "oldpkg\t1.0-1\trc \nlibc6\t2.36-9+rpt2+deb12u9\tii \nlibc6\t2.36-9+rpt2+deb12u9\tii \n")


def test_packages_debian_pi_ecosystem_and_installed_only():
    out = pk.LinuxPackages().run(FixtureContext(PI, {"commands": {pk.DPKG_QUERY.name: {"stdout": DPKG}}}))
    names = {s.name for s in out.software}
    assert "oldpkg" not in names and len(out.software) == 8  # rc filtered, duplicate multi-arch line deduped
    assert {s.ecosystem for s in out.software} == {"Debian:12"}
    ev = out.evidence[0].content
    assert "raspberrypi.com" in ev["note"] and "lower confidence" in ev["note"]
    assert ev["raspberry_pi_archive_versions"] == ["libc6", "libcamera0.5"]
    assert out.findings == []


def test_packages_are_listed_by_source_package_for_advisory_matching():
    text = ("libssl3\t3.0.15-1~deb12u1\tii \topenssl\t3.0.15-1~deb12u1\n"
            "openssl\t3.0.15-1~deb12u1\tii \topenssl\t3.0.15-1~deb12u1\n"
            "bash\t5.2.15-2+b8\tii \tbash\t5.2.15-2\n"
            "libc6\t2.36-9+rpt2+deb12u12\tii \tglibc\t2.36-9+rpt2+deb12u12\n")
    out = pk.LinuxPackages().run(FixtureContext(PI, {"commands": {pk.DPKG_QUERY.name: {"stdout": text}}}))
    assert sorted((s.name, s.version) for s in out.software) == [
        ("bash", "5.2.15-2"), ("glibc", "2.36-9+rpt2+deb12u12"), ("openssl", "3.0.15-1~deb12u1")]
    ev = out.evidence[0].content
    assert ev["listed_by"] == "source package"
    assert ev["binary_packages_mapped_to_source"] == {"libc6": "glibc", "libssl3": "openssl"}


@pytest.mark.parametrize("version,expected", [("24.04", "Ubuntu:24.04:LTS"), ("22.04", "Ubuntu:22.04:LTS"),
                                              ("20.04", "Ubuntu:20.04:LTS"), ("26.04", "Ubuntu:26.04:LTS"),
                                              ("25.10", "Ubuntu:25.10"), ("23.04", "Ubuntu:23.04")])
def test_ubuntu_ecosystem(version, expected):
    assert pk.ubuntu_ecosystem(version) == expected


def test_packages_raspbian_and_rpm_fallback():
    assert pk.ecosystem_for(linux_host(distro_id="raspbian", distro_version="12"))[0] == "Debian:12"
    fedora = linux_host(distro_id="fedora", distro_version="40")
    fixture = {"commands": {pk.DPKG_QUERY.name: {"error": "not_found", "message": "dpkg-query is not installed"},
                            pk.RPM_QUERY.name: {"stdout": "bash\t0:5.2.26-3.fc40\ngpg-pubkey\t0:a15b79cc-63d04c2c\n"}}}
    out = pk.LinuxPackages().run(FixtureContext(fedora, fixture))
    assert [(s.name, s.version, s.source) for s in out.software] == [("bash", "0:5.2.26-3.fc40", "rpm")]


def test_packages_no_package_manager_skips():
    missing = {"error": "not_found", "message": "not installed"}
    with pytest.raises(SkipCheck):
        pk.LinuxPackages().run(FixtureContext(PI, {"commands": {pk.DPKG_QUERY.name: missing,
                                                                pk.RPM_QUERY.name: missing}}))


# --------------------------------------------------------------------------- linux.logs.auth

T0 = 1761350400_000000  # 2025-10-25T00:00:00Z in microseconds


def jline(i, comm, message, pid="2201", ts=None):
    return json.dumps({
        "__CURSOR": f"s=4c1f8a0b2e7d4b6f9a3c5d7e9f1a2b3c;i={i:x};b=7e2d9c4a1b3f;m={i * 1000:x};t={T0 + i:x};x={i:016x}",
        "__REALTIME_TIMESTAMP": str(ts if ts is not None else T0 + i * 1_000_000), "_COMM": comm,
        "SYSLOG_IDENTIFIER": comm.split("-")[0], "_PID": pid, "_HOSTNAME": "pi5", "MESSAGE": message,
    })


JOURNAL = "\n".join([
    jline(1, "sshd", "Invalid user admin from 203.0.113.50 port 50812", pid="3001"),
    jline(2, "sshd", "Failed password for invalid user admin from 203.0.113.50 port 50812 ssh2", pid="3001"),
    jline(3, "sshd", "Failed password for root from 203.0.113.50 port 50820 ssh2", pid="3002"),
    jline(4, "sshd", "Invalid user oracle from 198.51.100.9 port 41000", pid="3003"),
    jline(5, "sshd", "Connection closed by invalid user oracle 198.51.100.9 port 41000 [preauth]", pid="3003"),
    jline(6, "sshd-session", "Accepted publickey for pi from 192.168.1.20 port 51234 ssh2: ED25519 SHA256:abc",
          pid="3004"),
    jline(7, "sudo", "pam_unix(sudo:auth): authentication failure; logname=pi uid=1000 euid=0 tty=/dev/pts/0 "
          "ruser=pi rhost=  user=pi", pid="3100"),
    jline(8, "sudo", "      pi : 3 incorrect password attempts ; TTY=pts/0 ; PWD=/home/pi ; USER=root ; "
          "COMMAND=/usr/bin/apt update", pid="3100"),
    jline(9, "sudo", "      pi : TTY=pts/0 ; PWD=/home/pi ; USER=root ; COMMAND=/usr/bin/systemctl restart ssh",
          pid="3101"),
    jline(10, "sudo", "pam_unix(sudo:session): session opened for user root(uid=0) by pi(uid=1000)", pid="3101"),
]) + "\n"


def test_auth_log_parses_ssh_and_sudo_and_saves_cursor():
    state = MemoryState()
    ctx = FixtureContext(PI, {"commands": {al.JOURNAL_FIRST_RUN.name: {"stdout": JOURNAL}}}, state=state)
    out = al.LinuxAuthLog().run(ctx)
    got = [(e.action, e.user, e.source_ip) for e in out.events]
    assert got == [
        ("ssh_failed", "admin", "203.0.113.50"),  # the "Invalid user" line of the same connection is not double counted
        ("ssh_failed", "root", "203.0.113.50"),
        ("ssh_failed", "oracle", "198.51.100.9"),  # key-only servers log only "Invalid user"
        ("ssh_success", "pi", "192.168.1.20"),
        ("sudo_failed", "pi", None),
        ("sudo_failed", "pi", None),
        ("sudo_command", "pi", None),
    ]
    assert out.events[0].occurred_at.isoformat() == "2025-10-25T00:00:02+00:00"
    assert out.events[0].severity is Severity.LOW and out.events[0].outcome == "failure"
    assert out.events[4].severity is Severity.MEDIUM
    assert out.events[6].data["command"] == "/usr/bin/systemctl restart ssh"
    assert out.events[0].record_id.startswith("s=4c1f8a0b") and out.events[0].source == "linux:journal"
    assert state.get("cursor:linux:journal-auth") == json.loads(JOURNAL.splitlines()[-1])["__CURSOR"]
    assert ctx.calls == [(al.JOURNAL_FIRST_RUN.name, {})]


def test_auth_log_uses_saved_cursor_and_quiet_period_passes():
    cursor = json.loads(jline(10, "sudo", "x"))["__CURSOR"]
    state = MemoryState({"cursor:linux:journal-auth": cursor})
    ctx = FixtureContext(PI, {"commands": {al.JOURNAL_AFTER_CURSOR.name: {"stdout": ""}}}, state=state)
    out = al.LinuxAuthLog().run(ctx)
    assert out.events == [] and ctx.calls == [(al.JOURNAL_AFTER_CURSOR.name, {"cursor": cursor})]
    assert al.JOURNAL_AFTER_CURSOR.render({"cursor": cursor})[5:7] == ["--after-cursor", cursor]
    assert state.get("cursor:linux:journal-auth") == cursor


def test_auth_log_permission_denied_skips_with_group_hint():
    hint = ("Hint: You are currently not seeing messages from other users and the system.\n"
            "      Users in groups 'adm', 'systemd-journal' can see all messages.\n")
    fixture = {"commands": {al.JOURNAL_FIRST_RUN.name: {"stdout": "", "stderr": hint}}}
    with pytest.raises(SkipCheck, match="systemd-journal"):
        al.LinuxAuthLog().run(FixtureContext(PI, fixture))


def test_auth_log_without_journalctl_skips():
    fixture = {"commands": {al.JOURNAL_FIRST_RUN.name: {"error": "not_found", "message": "journalctl is not installed"}}}
    with pytest.raises(SkipCheck, match="journalctl is not installed"):
        al.LinuxAuthLog().run(FixtureContext(PI, fixture))


def test_auth_log_stale_cursor_falls_back_to_last_week():
    state = MemoryState({"cursor:linux:journal-auth": "s=dead;i=1"})
    fixture = {"commands": {al.JOURNAL_AFTER_CURSOR.name: {"exit_code": 1, "stdout": "",
                                                           "stderr": "Failed to seek to cursor: Invalid argument"},
                            al.JOURNAL_FIRST_RUN.name: {"stdout": jline(1, "sshd", "Failed password for pi from "
                                                                                   "10.0.0.5 port 1 ssh2") + "\n"}}}
    out = al.LinuxAuthLog().run(FixtureContext(PI, fixture, state=state))
    assert [e.action for e in out.events] == ["ssh_failed"]
    assert "no longer valid" in out.evidence[0].content["window"]


def test_auth_log_exit_1_without_message_means_no_entries():
    fixture = {"commands": {al.JOURNAL_FIRST_RUN.name: {"exit_code": 1, "stdout": "", "stderr": ""}}}
    out = al.LinuxAuthLog().run(FixtureContext(PI, fixture))
    assert out.events == [] and out.evidence[0].content["entries_read"] == 0
