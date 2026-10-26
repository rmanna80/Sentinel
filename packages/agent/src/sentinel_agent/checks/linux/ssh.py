"""OpenSSH server configuration.

How sshd resolves settings (and how this check models it):

* For most keywords the FIRST value sshd reads wins; later lines for the same keyword are ignored.
* ``Include`` is expanded in place. Debian, Ubuntu and Raspberry Pi OS ship
  ``Include /etc/ssh/sshd_config.d/*.conf`` as the first directive of sshd_config, so drop-in files are read
  before the rest of the main file and override it. The check follows the Include line where it appears; if
  the main file has no Include for sshd_config.d, the drop-ins are listed in evidence but not applied.
* Files matched by a glob are read in lexical order.
* Lines after a ``Match`` keyword apply only to matching connections; they are ignored for the global
  result (until the end of that file).
"""

from __future__ import annotations

import fnmatch
import posixpath
import shlex

from sentinel_core.checks import Check, CheckContext, NotApplicable, SkipCheck
from sentinel_core.models import CheckOutput, Platform, Severity

from ...context import PathNotAllowed
from .._util import finding

SSHD_CONFIG = "/etc/ssh/sshd_config"
DROPIN_DIR = "/etc/ssh/sshd_config.d"
WATCHED = ("permitrootlogin", "passwordauthentication", "kbdinteractiveauthentication", "pubkeyauthentication",
           "permitemptypasswords", "port", "listenaddress")
DEFAULTS = {"permitrootlogin": "prohibit-password", "passwordauthentication": "yes", "permitemptypasswords": "no"}


def _tokens(line: str) -> list[str]:
    line = line.strip()
    if not line or line.startswith("#"):
        return []
    try:
        return shlex.split(line, comments=True)
    except ValueError:
        return line.split()


class SshdConfig:
    def __init__(self, ctx: CheckContext) -> None:
        self.ctx = ctx
        self.values: dict[str, tuple[str, str]] = {}  # keyword -> (value, file)
        self.files_read: list[str] = []
        self.unreadable: list[str] = []
        self.includes_unsupported: list[str] = []

    def _expand(self, pattern: str) -> list[str]:
        if not pattern.startswith("/"):
            pattern = posixpath.join("/etc/ssh", pattern)
        folder, glob = posixpath.split(pattern)
        if folder != DROPIN_DIR and pattern != SSHD_CONFIG:
            self.includes_unsupported.append(pattern)
            return []
        try:
            names = self.ctx.list_dir(folder)
        except (OSError, PathNotAllowed):
            self.unreadable.append(folder)
            return []
        return [posixpath.join(folder, n) for n in sorted(names) if fnmatch.fnmatchcase(n, glob)]

    def read(self, path: str, depth: int = 0) -> None:
        if depth > 4:
            return
        try:
            text = self.ctx.read_text(path)
        except PermissionError:
            self.unreadable.append(path)
            return
        except (OSError, PathNotAllowed):
            if path == SSHD_CONFIG:
                raise
            self.unreadable.append(path)
            return
        self.files_read.append(path)
        for line in text.splitlines():
            tok = _tokens(line)
            if not tok:
                continue
            key = tok[0].lower()
            if "=" in key:  # "Keyword=value" form
                key, _, first = key.partition("=")
                tok = [key, first, *tok[1:]]
            if key == "match":
                return
            if key == "include":
                for pattern in tok[1:]:
                    for inc in self._expand(pattern):
                        self.read(inc, depth + 1)
                continue
            if key in WATCHED and key not in self.values and len(tok) > 1:
                self.values[key] = (tok[1], path)


class SshServerConfig(Check):
    id = "linux.ssh_config"
    version = "1"
    title = "The SSH server does not allow root or password sign-ins"
    category = "configuration"
    platforms = frozenset({Platform.LINUX})
    data_collected = (
        "Sign-in settings (PermitRootLogin, PasswordAuthentication, KbdInteractiveAuthentication, "
        "PubkeyAuthentication, PermitEmptyPasswords, Port, ListenAddress) from /etc/ssh/sshd_config and "
        "/etc/ssh/sshd_config.d/*.conf"
    )

    def run(self, ctx: CheckContext) -> CheckOutput:
        if not ctx.path_exists(SSHD_CONFIG):
            raise NotApplicable("OpenSSH server not installed")
        cfg = SshdConfig(ctx)
        try:
            cfg.read(SSHD_CONFIG)
        except (OSError, PathNotAllowed) as exc:
            raise SkipCheck(f"{SSHD_CONFIG} could not be read") from exc
        try:
            dropins = sorted(ctx.list_dir(DROPIN_DIR))
        except (OSError, PathNotAllowed):
            dropins = []
        effective = {k: cfg.values[k][0] if k in cfg.values else DEFAULTS.get(k) for k in WATCHED}
        evidence = [ctx.evidence("file_metadata", SSHD_CONFIG, {
            "effective": effective,
            "set_in": {k: v[1] for k, v in cfg.values.items()},
            "defaults_assumed": sorted(k for k in DEFAULTS if k not in cfg.values),
            "files_read": cfg.files_read,
            "dropins_present": dropins,
            "unreadable": cfg.unreadable,
            "includes_not_followed": cfg.includes_unsupported,
            "model": "First value wins; Include is expanded where it appears (Debian puts it first, so "
                     "sshd_config.d/*.conf overrides sshd_config); Match blocks are ignored.",
        })]
        findings = []
        root = str(effective.get("permitrootlogin") or "").lower()
        if root == "yes":
            findings.append(finding(
                "linux.ssh_config.root_login", "sshd:PermitRootLogin",
                "SSH allows signing in directly as root",
                Severity.HIGH,
                "Attackers only need to guess one well-known account name, and a successful guess gives full "
                "control of the machine.",
                "Set `PermitRootLogin no` (or `prohibit-password`) in /etc/ssh/sshd_config.d/ and restart ssh "
                "(`sudo systemctl restart ssh`). Sign in as a normal user and use sudo instead.",
            ))
        pw = str(effective.get("passwordauthentication") or "").lower()
        if pw == "yes":
            unset = "passwordauthentication" not in cfg.values
            findings.append(finding(
                "linux.ssh_config.password_auth", "sshd:PasswordAuthentication",
                "SSH accepts passwords" + (" (not set, and OpenSSH's default is yes)" if unset else ""),
                Severity.MEDIUM,
                "Anyone who can reach port 22 can try to guess passwords. Internet-facing SSH servers see "
                "thousands of guesses a day.",
                "Set up key-based sign-in first (`ssh-copy-id` from your computer), confirm it works, then add "
                "`PasswordAuthentication no` to a file in /etc/ssh/sshd_config.d/ and restart ssh.",
            ))
        return CheckOutput(evidence=evidence, findings=findings)
