"""SystemProbe implementations: live (psutil) and fixture-backed."""

from __future__ import annotations

import socket
import threading
from collections.abc import Mapping
from typing import Any

_FAMILIES = {socket.AF_INET: "ipv4", socket.AF_INET6: "ipv6"}


class PsutilProbe:
    def __init__(self, recorder: Any | None = None) -> None:
        self._recorder = recorder
        self._lock = threading.Lock()

    def _rec(self, name: str, value: Any) -> Any:
        if self._recorder is not None:
            with self._recorder.lock:
                self._recorder.files[f"<system>::{name}"] = value
        return value

    def cpu_percent(self) -> float:
        import psutil

        return float(self._rec("cpu_percent", psutil.cpu_percent(interval=0.5)))

    def memory(self) -> dict[str, Any]:
        import psutil

        vm = psutil.virtual_memory()
        return self._rec("memory", {"total": vm.total, "available": vm.available, "percent": vm.percent})

    def disks(self) -> list[dict[str, Any]]:
        import psutil

        out = []
        for part in psutil.disk_partitions(all=False):
            if "cdrom" in part.opts or not part.fstype:
                continue
            try:
                u = psutil.disk_usage(part.mountpoint)
            except OSError:
                continue
            out.append({"mountpoint": part.mountpoint, "fstype": part.fstype, "total": u.total, "used": u.used,
                        "free": u.free, "percent": u.percent})
        return self._rec("disks", out)

    def boot_time(self) -> float:
        import psutil

        return float(self._rec("boot_time", psutil.boot_time()))

    def _proc_name(self, pid: int | None, cache: dict[int, str | None]) -> str | None:
        import psutil

        if not pid:
            return None
        if pid not in cache:
            try:
                cache[pid] = psutil.Process(pid).name()
            except (psutil.Error, OSError):
                cache[pid] = None
        return cache[pid]

    def listening_sockets(self) -> list[dict[str, Any]]:
        import psutil

        cache: dict[int, str | None] = {}
        out = []
        try:
            conns = psutil.net_connections(kind="inet")
        except (psutil.AccessDenied, OSError):
            conns = []
        for c in conns:
            is_tcp_listen = c.type == socket.SOCK_STREAM and c.status == psutil.CONN_LISTEN
            is_udp = c.type == socket.SOCK_DGRAM and not c.raddr
            if not (is_tcp_listen or is_udp) or not c.laddr:
                continue
            out.append({"proto": "tcp" if c.type == socket.SOCK_STREAM else "udp", "ip": c.laddr.ip,
                        "port": c.laddr.port, "pid": c.pid, "process": self._proc_name(c.pid, cache)})
        return self._rec("listening_sockets", out)

    def connections(self) -> list[dict[str, Any]]:
        import psutil

        cache: dict[int, str | None] = {}
        out = []
        try:
            conns = psutil.net_connections(kind="inet")
        except (psutil.AccessDenied, OSError):
            conns = []
        for c in conns:
            if c.status != psutil.CONN_ESTABLISHED or not c.raddr:
                continue
            out.append({"proto": "tcp", "laddr": c.laddr.ip, "lport": c.laddr.port, "raddr": c.raddr.ip,
                        "rport": c.raddr.port, "pid": c.pid, "process": self._proc_name(c.pid, cache)})
        return self._rec("connections", out)

    def interfaces(self) -> list[dict[str, Any]]:
        import psutil

        stats = psutil.net_if_stats()
        out = []
        for name, addrs in psutil.net_if_addrs().items():
            st = stats.get(name)
            out.append({
                "name": name,
                "is_up": bool(st.isup) if st else False,
                "mtu": st.mtu if st else None,
                "speed": st.speed if st else None,
                "addresses": [
                    {"family": _FAMILIES[a.family], "address": a.address, "netmask": a.netmask}
                    for a in addrs if a.family in _FAMILIES
                ],
            })
        return self._rec("interfaces", out)

    def processes(self) -> list[dict[str, Any]]:
        import psutil

        out = []
        for p in psutil.process_iter(["pid", "name", "exe", "username", "create_time"]):
            info = p.info
            out.append({k: info.get(k) for k in ("pid", "name", "exe", "username", "create_time")})
        return self._rec("processes", out)


class FixtureProbe:
    def __init__(self, data: Mapping[str, Any] | None) -> None:
        self._d = dict(data or {})

    def _get(self, name: str, default: Any) -> Any:
        return self._d.get(f"<system>::{name}", self._d.get(name, default))

    def cpu_percent(self) -> float:
        return float(self._get("cpu_percent", 0.0))

    def memory(self) -> dict[str, Any]:
        return dict(self._get("memory", {"total": 0, "available": 0, "percent": 0.0}))

    def disks(self) -> list[dict[str, Any]]:
        return list(self._get("disks", []))

    def boot_time(self) -> float:
        return float(self._get("boot_time", 0.0))

    def listening_sockets(self) -> list[dict[str, Any]]:
        return list(self._get("listening_sockets", []))

    def connections(self) -> list[dict[str, Any]]:
        return list(self._get("connections", []))

    def interfaces(self) -> list[dict[str, Any]]:
        return list(self._get("interfaces", []))

    def processes(self) -> list[dict[str, Any]]:
        return list(self._get("processes", []))
