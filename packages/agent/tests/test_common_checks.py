"""Checks that run on Windows and Linux, against hand-written fixtures (not recordings)."""

import json

import pytest
from sentinel_agent.checks.common import dependencies as dep
from sentinel_agent.checks.common import network as net
from sentinel_agent.testing import FixtureContext, linux_host, ps_json, windows_host
from sentinel_core.checks import SkipCheck
from sentinel_core.models import Confidence, FindingKind, Severity

ANY_V4 = "0.0.0.0"  # noqa: S104 - a socket address in fixture data, nothing binds to it


def rules(out):
    return sorted(f.rule_id for f in out.findings)


# --------------------------------------------------------------------------- net.listening


def test_listening_flags_exposed_services_by_severity():
    sockets = [
        {"proto": "tcp", "ip": ANY_V4, "port": 23, "pid": 900, "process": "telnetd"},
        {"proto": "tcp", "ip": ANY_V4, "port": 445, "pid": 4, "process": None},
        {"proto": "tcp", "ip": "::", "port": 445, "pid": 4, "process": None},
        {"proto": "tcp", "ip": "192.168.1.20", "port": 22, "pid": 711, "process": "sshd"},
        {"proto": "tcp", "ip": "127.0.0.1", "port": 6379, "pid": 1200, "process": "redis-server"},
        {"proto": "tcp", "ip": "::1", "port": 5432, "pid": 1300, "process": "postgres"},
        {"proto": "udp", "ip": ANY_V4, "port": 5353, "pid": 2000, "process": "avahi-daemon"},
    ]
    out = net.ListeningPorts().run(FixtureContext(linux_host(), {"system": {"listening_sockets": sockets}}))
    by_key = {f.subject_key: f for f in out.findings}
    assert set(by_key) == {"tcp:0.0.0.0:23", "tcp:0.0.0.0:445", "tcp::::445", "tcp:192.168.1.20:22"}
    assert by_key["tcp:0.0.0.0:23"].severity is Severity.HIGH
    assert by_key["tcp:0.0.0.0:445"].severity is Severity.LOW  # on by default on Windows
    assert by_key["tcp:192.168.1.20:22"].kind is FindingKind.INFORMATIONAL
    assert "admin rights" in out.evidence[0].content["note"]


def test_listening_loopback_only_passes():
    sockets = [{"proto": "tcp", "ip": "127.0.0.1", "port": 3306, "pid": 1, "process": "mysqld"},
               {"proto": "tcp", "ip": ANY_V4, "port": 8765, "pid": 2, "process": "python.exe"}]
    out = net.ListeningPorts().run(FixtureContext(windows_host(), {"system": {"listening_sockets": sockets}}))
    assert out.findings == []


# --------------------------------------------------------------------------- proc.suspicious_locations


def test_processes_in_temp_folders_are_heuristic():
    procs = [
        {"pid": 1, "name": "explorer.exe", "exe": "C:\\Windows\\explorer.exe", "username": "RYAN-PC\\Ryan"},
        {"pid": 2, "name": "svch0st.exe", "exe": "C:\\Users\\Ryan\\AppData\\Local\\Temp\\svch0st.exe",
         "username": "RYAN-PC\\Ryan"},
        {"pid": 3, "name": "setup.exe", "exe": "C:\\Users\\Ryan\\Downloads\\setup.exe", "username": "RYAN-PC\\Ryan"},
        {"pid": 4, "name": "System", "exe": None, "username": None},
        {"pid": 5, "name": "xmrig", "exe": "/dev/shm/.x/xmrig", "username": "www-data"},
        {"pid": 6, "name": "bash", "exe": "/usr/bin/bash", "username": "pi"},
    ]
    out = net.SuspiciousProcessLocations().run(FixtureContext(windows_host(), {"system": {"processes": procs}}))
    assert len(out.findings) == 3
    assert {(f.kind, f.confidence, f.severity) for f in out.findings} == {
        (FindingKind.HEURISTIC, Confidence.MEDIUM, Severity.MEDIUM)}
    assert all("not proof of malware" in f.impact for f in out.findings)
    assert out.evidence[0].content["without_path"] == 1


def test_processes_in_normal_locations_pass():
    procs = [{"pid": 1, "name": "sshd", "exe": "/usr/sbin/sshd", "username": "root"},
             {"pid": 2, "name": "python3", "exe": "/home/pi/venv/bin/python3", "username": "pi"}]
    out = net.SuspiciousProcessLocations().run(FixtureContext(linux_host(), {"system": {"processes": procs}}))
    assert out.findings == []


# --------------------------------------------------------------------------- net.unusual_outbound


def _conn(rport, process="chrome.exe", raddr="142.250.65.78", pid=10):
    return {"proto": "tcp", "laddr": "192.168.1.20", "lport": 50000 + rport % 1000, "raddr": raddr, "rport": rport,
            "pid": pid, "process": process}


def test_unusual_ports_and_many_connections():
    conns = [_conn(4444, "rundll32.exe", "198.51.100.7", 77), _conn(9001, "tor.exe", "203.0.113.4", 78)]
    conns += [_conn(443) for _ in range(51)]
    out = net.UnusualOutbound().run(FixtureContext(windows_host(), {"system": {"connections": conns}}))
    ports = [f for f in out.findings if f.rule_id == "net.unusual_outbound.port"]
    assert {(f.severity, f.confidence, f.kind) for f in ports} == {(Severity.LOW, Confidence.LOW, FindingKind.HEURISTIC)}
    assert len(ports) == 2
    many = [f for f in out.findings if f.rule_id == "net.unusual_outbound.many_connections"]
    assert len(many) == 1 and many[0].kind is FindingKind.INFORMATIONAL and "chrome.exe" in many[0].title


def test_ordinary_outbound_passes():
    conns = [_conn(443), _conn(80, "firefox.exe"), _conn(22, "ssh.exe")]
    assert net.UnusualOutbound().run(FixtureContext(windows_host(), {"system": {"connections": conns}})).findings == []


# --------------------------------------------------------------------------- net.dns_config

IFACES = [
    {"name": "Wi-Fi", "is_up": True,
     "addresses": [{"family": "ipv4", "address": "192.168.1.20", "netmask": "255.255.255.0"}]},
    {"name": "Ethernet", "is_up": False, "addresses": []},
    {"name": "Loopback Pseudo-Interface 1", "is_up": True,
     "addresses": [{"family": "ipv4", "address": "127.0.0.1", "netmask": "255.0.0.0"}]},
]


def test_dns_windows_configured_passes():
    rows = [{"InterfaceAlias": "Wi-Fi", "InterfaceIndex": 12, "AddressFamily": "IPv4", "ServerAddresses": ["192.168.1.1"]},
            {"InterfaceAlias": "Wi-Fi", "InterfaceIndex": 12, "AddressFamily": "IPv6", "ServerAddresses": []},
            {"InterfaceAlias": "Ethernet", "InterfaceIndex": 7, "AddressFamily": "IPv4", "ServerAddresses": []}]
    fixture = {"commands": {net.DNS_SERVERS.name: ps_json(rows)}, "system": {"interfaces": IFACES}}
    out = net.DnsConfiguration().run(FixtureContext(windows_host(), fixture))
    assert out.findings == []


def test_dns_windows_up_interface_without_servers_is_low():
    rows = [{"InterfaceAlias": "Wi-Fi", "AddressFamily": "IPv4", "ServerAddresses": {"value": [], "Count": 0}}]
    fixture = {"commands": {net.DNS_SERVERS.name: ps_json(rows)}, "system": {"interfaces": IFACES}}
    out = net.DnsConfiguration().run(FixtureContext(windows_host(), fixture))
    assert rules(out) == ["net.dns_config.no_servers"] and out.findings[0].severity is Severity.LOW


def test_dns_windows_virtual_adapter_without_servers_is_not_flagged():
    wsl = {"name": "vEthernet (WSL)", "is_up": True,
           "addresses": [{"family": "ipv4", "address": "172.29.208.1", "netmask": "255.255.240.0"}]}
    rows = [{"InterfaceAlias": "Wi-Fi", "AddressFamily": "IPv4", "ServerAddresses": ["192.168.1.1"]},
            {"InterfaceAlias": "vEthernet (WSL)", "AddressFamily": "IPv4", "ServerAddresses": []}]
    fixture = {"commands": {net.DNS_SERVERS.name: ps_json(rows)}, "system": {"interfaces": [*IFACES, wsl]}}
    out = net.DnsConfiguration().run(FixtureContext(windows_host(), fixture))
    assert out.findings == []
    assert out.evidence[0].content["up_interfaces_without_dns"] == ["vEthernet (WSL)"]


def test_dns_linux_systemd_resolved_stub_is_explained():
    fixture = {"files": {"/etc/resolv.conf": "# managed by systemd-resolved\nnameserver 127.0.0.53\noptions edns0\n"},
               "system": {"interfaces": IFACES}}
    out = net.DnsConfiguration().run(FixtureContext(linux_host(), fixture))
    assert out.findings == []
    assert "systemd-resolved" in out.evidence[0].content["notes"][0]


def test_dns_linux_empty_resolv_conf_is_low():
    fixture = {"files": {"/etc/resolv.conf": "# nothing here\n"}, "system": {"interfaces": IFACES}}
    assert rules(net.DnsConfiguration().run(FixtureContext(linux_host(), fixture))) == ["net.dns_config.no_servers"]


# --------------------------------------------------------------------------- net.interfaces


def test_interfaces_private_addresses_pass():
    out = net.NetworkInterfaces().run(FixtureContext(linux_host(), {"system": {"interfaces": IFACES}}))
    assert out.findings == [] and out.evidence[0].content == IFACES


def test_interfaces_public_ipv4_is_informational():
    ifaces = [{"name": "eth0", "is_up": True, "addresses": [{"family": "ipv4", "address": "8.8.4.4", "netmask": None},
                                                             {"family": "ipv4", "address": "100.64.0.5", "netmask": None}]}]
    out = net.NetworkInterfaces().run(FixtureContext(linux_host(), {"system": {"interfaces": ifaces}}))
    assert [f.kind for f in out.findings] == [FindingKind.INFORMATIONAL]  # CGNAT 100.64/10 is not public
    assert out.findings[0].subject_key == "iface:eth0:8.8.4.4"


# --------------------------------------------------------------------------- dev.dependencies

REQUIREMENTS = """# app requirements
-r base.txt
--index-url https://pypi.org/simple
-e git+https://github.com/example/lib.git#egg=lib
Django==4.2.7  # web
requests[socks]==2.31.0 ; python_version >= "3.8"
Pillow>=10.0
numpy == 1.26.4 \\
    --hash=sha256:abc
zope.interface==6.1
pkg @ https://example.invalid/pkg.whl
"""
LOCK = {
    "name": "site", "version": "1.0.0", "lockfileVersion": 3,
    "packages": {
        "": {"name": "site", "version": "1.0.0", "dependencies": {"lodash": "^4.17.20"}},
        "node_modules/lodash": {"version": "4.17.20"},
        "node_modules/@babel/core": {"version": "7.23.2"},
        "node_modules/@babel/core/node_modules/semver": {"version": "6.3.0"},
        "packages/ui": {"name": "ui", "version": "0.0.1"},
        "node_modules/ui": {"resolved": "packages/ui", "link": True},
    },
}
PROJECT = "/home/ryan/code/site"


def test_dependencies_requires_configured_folders():
    with pytest.raises(SkipCheck) as exc:
        dep.ProjectDependencies().run(FixtureContext(linux_host(), {}))
    assert str(exc.value) == "No project folders configured. Add one with: sentinel-agent config --add-project-path <folder>"


def test_dependencies_reads_pins_and_lockfile():
    fixture = {"files": {PROJECT + "::<listdir>": "requirements.txt\npackage-lock.json\nsrc",
                         PROJECT + "/requirements.txt": REQUIREMENTS,
                         PROJECT + "/package-lock.json": json.dumps(LOCK)}}
    out = dep.ProjectDependencies().run(FixtureContext(linux_host(), fixture, config={"project_paths": [PROJECT]}))
    got = {(s.ecosystem, s.name, s.version) for s in out.software}
    assert got == {("PyPI", "django", "4.2.7"), ("PyPI", "requests", "2.31.0"), ("PyPI", "numpy", "1.26.4"),
                   ("PyPI", "zope-interface", "6.1"), ("npm", "lodash", "4.17.20"), ("npm", "@babel/core", "7.23.2"),
                   ("npm", "semver", "6.3.0")}
    assert {s.location for s in out.software} == {PROJECT}
    assert out.evidence[0].content["projects"][0]["requirements.txt"] == {"pinned": 4, "not_pinned": 2}
    assert out.findings == []


def test_dependencies_old_lockfile_and_empty_folder():
    old = {"lockfileVersion": 1, "dependencies": {"lodash": {"version": "4.17.20"}}}
    fixture = {"files": {PROJECT + "::<listdir>": "package-lock.json", PROJECT + "/package-lock.json": json.dumps(old),
                         "/home/ryan/empty::<listdir>": "README.md"}}
    ctx = FixtureContext(linux_host(), fixture, config={"project_paths": [PROJECT, "/home/ryan/empty"]})
    out = dep.ProjectDependencies().run(ctx)
    assert out.software == []
    projects = out.evidence[0].content["projects"]
    assert projects[0]["package-lock.json"]["note"] == "Only lockfileVersion 2 and 3 are read"
    assert "No requirements.txt" in projects[1]["note"]
