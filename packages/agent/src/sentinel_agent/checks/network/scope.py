"""Targets the network checks refuse, whatever the server asks (defense in depth).

The server is the scope authority: it decides what the owner is authorized to test. The agent still refuses
obviously unsafe parameters on its own: IPv4 ranges broader than /16, IPv6 ranges broader than /64, the
unspecified addresses (0.0.0.0, ::), multicast, and literal link-local addresses (169.254.0.0/16 and fe80::/10,
which include cloud metadata endpoints such as 169.254.169.254). IPv4-mapped IPv6 literals (::ffff:a.b.c.d)
and the numeric spellings resolvers accept as IPv4 (2852039166, 0xa9fea9fe, 169.254.43518, 0251.0376.0251.0376)
are judged as the IPv4 address they stand for. Hostnames are not resolved here.
"""

from __future__ import annotations

import ipaddress
import re
from ipaddress import IPv4Network, IPv6Network

MAX_IPV4_PREFIX = 16  # the broadest IPv4 range accepted is a /16
MAX_IPV6_PREFIX = 64  # the broadest IPv6 range accepted is a /64

_BLOCKED: tuple[tuple[IPv4Network | IPv6Network, str], ...] = (
    (IPv4Network("0.0.0.0/32"), "the unspecified address"),
    (IPv6Network("::/128"), "the unspecified address"),
    (IPv4Network("224.0.0.0/4"), "multicast addresses"),
    (IPv6Network("ff00::/8"), "multicast addresses"),
    (IPv4Network("169.254.0.0/16"), "link-local addresses (including cloud metadata endpoints)"),
    (IPv6Network("fe80::/10"), "link-local addresses"),
)
_V4_MAPPED = IPv6Network("::ffff:0:0/96")
_ATON_PART = re.compile(r"^(?:0[xX][0-9A-Fa-f]*|0[0-7]*|[1-9][0-9]*)$")


def inet_aton_address(text: str) -> ipaddress.IPv4Address | None:
    """The IPv4 address the system resolver (inet_aton) reads from ``text``, or None if it is not numeric.

    Accepts the classic forms ``ipaddress`` rejects: one to four dot-separated parts, each decimal, octal
    (leading 0) or hexadecimal (0x); the last part fills the remaining bytes.
    """
    parts = text.split(".")
    if not 1 <= len(parts) <= 4 or not all(_ATON_PART.match(p) for p in parts):
        return None
    values = [int(p[2:] or "0", 16) if p[:2].lower() == "0x" else int(p, 8) if p.startswith("0") else int(p)
              for p in parts]
    *head, last = values
    if any(v > 0xFF for v in head) or last >= 1 << (8 * (4 - len(head))):
        return None
    value = last
    for i, v in enumerate(head):
        value |= v << (24 - 8 * i)
    return ipaddress.IPv4Address(value)


def _as_network(target: str) -> IPv4Network | IPv6Network | None:
    host = target.strip().rstrip(".")
    try:
        return ipaddress.ip_network(host, strict=False)
    except ValueError:
        pass
    addr = inet_aton_address(host)
    return IPv4Network(addr) if addr is not None else None


def refusal(net: IPv4Network | IPv6Network) -> str | None:
    """Why the agent never contacts ``net``, or None."""
    if isinstance(net, IPv6Network) and net.overlaps(_V4_MAPPED):
        if not net.subnet_of(_V4_MAPPED):
            return "ranges that include IPv4-mapped addresses are not accepted"
        return refusal(IPv4Network((int(net.network_address) & 0xFFFFFFFF, net.prefixlen - 96)))
    limit = MAX_IPV4_PREFIX if net.version == 4 else MAX_IPV6_PREFIX
    if net.prefixlen < limit:
        return f"ranges broader than /{limit} are not accepted"
    for blocked, label in _BLOCKED:
        if blocked.version == net.version and net.overlaps(blocked):
            return f"{label} are never contacted"
    return None


def check_target(target: str) -> str:
    """Return ``target`` (an IP address, CIDR range or hostname) unchanged, or raise ValueError if the agent must
    never contact it."""
    net = _as_network(target)
    if net is not None and (why := refusal(net)) is not None:
        raise ValueError(f"{target!r}: {why}")
    return target
