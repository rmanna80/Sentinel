"""NVD CVE API 2.0, used only for a curated list of common Windows apps.

Since April 2026 NVD enriches only a subset of CVEs, so many records carry no CPE configuration or
NVD score. This module therefore:

* maps a Windows "Uninstall" DisplayName to CPE vendor:product pairs only through the curated
  ``CURATED_APPS`` list below (never by name similarity),
* downloads the CVEs NVD links to that product (``virtualMatchString``) and evaluates every
  configuration locally against the installed version with three-valued logic, so anything it
  cannot decide is "no match" instead of a guess,
* prefers NVD's own CVSS 3.x score and falls back to the CNA's ("Secondary") score, labelled as such,
* counts CVEs without any configuration as "not enriched" instead of turning them into findings.
"""

from __future__ import annotations

import re
import threading
import time
from collections import deque
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from .http import OutboundError, request

API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
PAGE_SIZE = 2000  # the documented maximum for resultsPerPage
WINDOW_SECONDS = 30.0
LIMIT_WITHOUT_KEY = 5
LIMIT_WITH_KEY = 50
NOT_ENRICHED_STATUSES = {"Received", "Awaiting Analysis", "Undergoing Analysis", "Deferred", "Not Scheduled",
                         "Lowest Priority", "Lowest Priority - not scheduled"}


class NvdError(Exception):
    pass


# =========================================================================== rate limiting


class RateLimited(Exception):
    def __init__(self, wait: float) -> None:
        super().__init__(f"NVD rate limit: next request allowed in {wait:.0f} s")
        self.wait = wait


class SlidingWindowLimiter:
    """At most ``limit`` acquisitions in any rolling ``window`` seconds, in this process."""

    def __init__(self, limit: int, window: float, *, clock: Callable[[], float] = time.monotonic,
                 sleep: Callable[[float], None] = time.sleep, margin: float = 0.5) -> None:
        self.limit = limit
        self.window = window
        self.clock = clock
        self.sleep = sleep
        self.margin = margin
        self._hits: deque[float] = deque()
        self._lock = threading.Lock()

    def _wait_needed(self, now: float) -> float:
        while self._hits and now - self._hits[0] >= self.window + self.margin:
            self._hits.popleft()
        if len(self._hits) < self.limit:
            return 0.0
        return self._hits[0] + self.window + self.margin - now

    def acquire(self, max_wait: float = 0.0) -> None:
        """Take one slot, sleeping up to ``max_wait`` seconds; raise ``RateLimited`` if that is not enough."""
        while True:
            with self._lock:
                now = self.clock()
                wait = self._wait_needed(now)
                if wait <= 0:
                    self._hits.append(now)
                    return
            if wait > max_wait:
                raise RateLimited(wait)
            self.sleep(wait)
            max_wait -= wait

    def reset(self) -> None:
        with self._lock:
            self._hits.clear()


_limiters = {False: SlidingWindowLimiter(LIMIT_WITHOUT_KEY, WINDOW_SECONDS),
             True: SlidingWindowLimiter(LIMIT_WITH_KEY, WINDOW_SECONDS)}


def limiter(with_key: bool) -> SlidingWindowLimiter:
    return _limiters[bool(with_key)]


# =========================================================================== version comparison

_PRE_RELEASE = {"dev": -5, "snapshot": -5, "alpha": -4, "a": -4, "beta": -3, "b": -3, "pre": -2, "preview": -2,
                "rc": -1, "c": -1, "cr": -1}
_NAMED_PRE = {"dev", "snapshot", "alpha", "beta", "pre", "preview", "rc", "cr"}
_TOKEN = re.compile(r"\d+|[a-z]+")
_LEADING_VERSION = re.compile(r"\d+(?:[.\-_+]?[0-9a-z]+)*", re.IGNORECASE)


def _tokens(version: str) -> list[int | str]:
    v = version.strip().lower()
    if v.startswith("v") and len(v) > 1 and v[1].isdigit():
        v = v[1:]
    out: list[int | str] = []
    for t in _TOKEN.findall(v):
        out.append(int(t) if t.isdigit() else t)
    return out


def _is_pre(tokens: list[int | str], i: int) -> bool:
    t = tokens[i]
    if not isinstance(t, str):
        return False
    if t in _NAMED_PRE:
        return True
    # a single a/b/c followed by a number is a pre-release (3.13.0b1); a trailing letter is a
    # post-release (OpenSSL 1.1.1w)
    return t in ("a", "b", "c") and i + 1 < len(tokens) and isinstance(tokens[i + 1], int)


def compare_generic(a: str | None, b: str | None) -> int | None:
    """Compare dotted versions with suffixes. Returns -1, 0, 1, or None when either is unusable.

    Numeric parts compare as numbers, trailing zeros are ignored (6.23.0 == 6.23), pre-release
    markers (dev, alpha, beta, rc, a1, b2) sort before the release, other trailing words and
    letters sort after it (1.1.1w > 1.1.1, 2.45.2.windows.1 > 2.45.2).
    """
    if not a or not b:
        return None
    ta, tb = _tokens(a), _tokens(b)
    if not ta or not tb or not isinstance(ta[0], int) or not isinstance(tb[0], int):
        return None
    i = 0
    while i < len(ta) and i < len(tb):
        x, y = ta[i], tb[i]
        if isinstance(x, int) and isinstance(y, int):
            if x != y:
                return -1 if x < y else 1
        elif isinstance(x, str) and isinstance(y, str):
            px, py = _is_pre(ta, i), _is_pre(tb, i)
            if px and py:
                rx, ry = _PRE_RELEASE.get(x, -3), _PRE_RELEASE.get(y, -3)
                if rx != ry:
                    return -1 if rx < ry else 1
            elif px != py:
                return -1 if px else 1
            elif x != y:
                return -1 if x < y else 1
        else:
            # number against word: a pre-release word is lower; any other word sorts below a number
            if isinstance(x, str):
                return -1
            return 1
        i += 1
    rest, sign = (ta[i:], 1) if i < len(ta) else (tb[i:], -1)
    if not rest:
        return 0
    first = rest[0]
    if isinstance(first, int):
        if all(isinstance(t, int) and t == 0 for t in rest):
            return 0
        return sign
    longer = ta if sign == 1 else tb
    return -sign if _is_pre(longer, i) else sign


def leading_version(raw: str | None) -> str | None:
    """'6.1.1 (41705)' -> '6.1.1'; returns None when there is no version number at all."""
    if not raw:
        return None
    m = _LEADING_VERSION.search(raw.strip())
    return m.group(0) if m else None


# =========================================================================== CPE handling


def split_cpe(cpe: str) -> list[str] | None:
    """Split a CPE 2.3 formatted string on unescaped colons; None when it is not one."""
    parts: list[str] = []
    cur: list[str] = []
    escaped = False
    for ch in cpe:
        if escaped:
            cur.append(ch)
            escaped = False
        elif ch == "\\":
            cur.append(ch)
            escaped = True
        elif ch == ":":
            parts.append("".join(cur))
            cur = []
        else:
            cur.append(ch)
    parts.append("".join(cur))
    if len(parts) != 13 or parts[0] != "cpe" or parts[1] != "2.3":
        return None
    return parts


@dataclass(frozen=True)
class Installed:
    """What we know about one installed app, for local configuration evaluation."""

    cpes: frozenset[tuple[str, str]]  # (vendor, product) in NVD spelling
    version: str
    update: str | None = None  # CPE "update" component, e.g. "update451" for Java 8
    sw_edition: str | None = None  # CPE "sw_edition", e.g. Adobe's "continuous" or "classic" track
    platform: str = "windows"
    windows_build: int | None = None


@dataclass
class ConfigMatch:
    criteria: str
    fixed_version: str | None  # versionEndExcluding of the matching criterion
    last_affected: str | None  # versionEndIncluding of the matching criterion


@dataclass
class _Eval:
    value: bool | None
    hits: list[ConfigMatch] = field(default_factory=list)


def _and(values: list[bool | None]) -> bool | None:
    if not values:
        return None
    if any(v is False for v in values):
        return False
    if all(v is True for v in values):
        return True
    return None


def _or(values: list[bool | None]) -> bool | None:
    if not values:
        return None
    if any(v is True for v in values):
        return True
    if all(v is False for v in values):
        return False
    return None


def _not(v: bool | None) -> bool | None:
    return None if v is None else not v


def _update_ok(criteria_update: str, inst: Installed) -> bool:
    if criteria_update == "*":
        return True
    if criteria_update == "-":
        return inst.update is None
    return inst.update is not None and criteria_update.lower() == inst.update.lower()


def _eval_ours(parts: list[str], m: dict[str, Any], inst: Installed) -> bool | None:
    version, update, sw_edition, target_sw = parts[5], parts[6], parts[9], parts[10]
    if target_sw not in ("*", "-", "") and not target_sw.startswith(inst.platform):
        return False  # e.g. the macOS build of the same product
    if sw_edition not in ("*", "-", ""):
        if inst.sw_edition is None:
            return None  # e.g. a release track we could not determine
        if sw_edition.lower() != inst.sw_edition.lower():
            return False
    if version not in ("*", "-"):
        c = compare_generic(inst.version, version.replace("\\", ""))
        if c is None:
            return None
        return c == 0 and _update_ok(update, inst)
    if version == "-":
        return None
    if update not in ("*", "-") and not _update_ok(update, inst):
        return False
    bounds = (("versionStartIncluding", lambda c: c >= 0), ("versionStartExcluding", lambda c: c > 0),
              ("versionEndIncluding", lambda c: c <= 0), ("versionEndExcluding", lambda c: c < 0))
    result = True
    for key, ok in bounds:
        bound = m.get(key)
        if not bound:
            continue
        c = compare_generic(inst.version, bound)
        if c is None:
            return None
        if c == 0 and inst.update is not None and update == "*":
            return None  # e.g. Java 1.8.0 update N against a bare 1.8.0 boundary: cannot tell
        if not ok(c):
            result = False
    return result


_WINDOWS_RELEASE_BUILDS = {
    "windows_11_21h2": 22000, "windows_11_22h2": 22621, "windows_11_23h2": 22631, "windows_11_24h2": 26100,
    "windows_11_25h2": 26200, "windows_10_21h2": 19044, "windows_10_22h2": 19045,
}


def _eval_platform(vendor: str, product: str, inst: Installed) -> bool | None:
    """Operating-system criteria on the other side of an AND: decided only for Windows, else unknown."""
    if vendor != "microsoft" or inst.platform != "windows":
        return None
    if product == "windows":
        return True
    if inst.windows_build is None:
        return None
    if product in _WINDOWS_RELEASE_BUILDS:
        return inst.windows_build == _WINDOWS_RELEASE_BUILDS[product]
    if product == "windows_11":
        return inst.windows_build >= 22000
    if product == "windows_10":
        return 10240 <= inst.windows_build < 22000
    return None  # server editions and anything unfamiliar: unknown


def _eval_cpe_match(m: dict[str, Any], inst: Installed) -> tuple[bool | None, bool]:
    """(truth value, whether this criterion is the installed app itself)."""
    parts = split_cpe(m.get("criteria", ""))
    if parts is None:
        return None, False
    part, vendor, product = parts[2], parts[3], parts[4]
    if part == "a" and (vendor, product) in inst.cpes:
        return _eval_ours(parts, m, inst), True
    if part == "o":
        return _eval_platform(vendor, product, inst), False
    return None, False  # another product we know nothing about: unknown, never assumed


def _eval_node(node: dict[str, Any], inst: Installed) -> _Eval:
    values: list[bool | None] = []
    hits: list[ConfigMatch] = []
    for m in node.get("cpeMatch") or []:
        value, ours = _eval_cpe_match(m, inst)
        values.append(value)
        if ours and value is True and m.get("vulnerable"):
            hits.append(ConfigMatch(criteria=m.get("criteria", ""), fixed_version=m.get("versionEndExcluding"),
                                    last_affected=m.get("versionEndIncluding")))
    value = _and(values) if (node.get("operator") or "OR").upper() == "AND" else _or(values)
    if node.get("negate"):
        return _Eval(_not(value), [])  # a negated node can never be the vulnerable part
    return _Eval(value, hits)


def has_configurations(cve: dict[str, Any]) -> bool:
    return any((cfg.get("nodes") or []) for cfg in cve.get("configurations") or [])


@dataclass
class Verdict:
    """affected | not_affected | unknown (data present but undecidable) | no_config (not enriched)."""

    status: str
    match: ConfigMatch | None = None


def evaluate(cve: dict[str, Any], inst: Installed) -> Verdict:
    """Evaluate every configuration locally; 'affected' only when one is definitely satisfied with the
    installed app as a vulnerable part."""
    if not has_configurations(cve):
        return Verdict("no_config")
    unknown = False
    for cfg in cve.get("configurations") or []:
        nodes = [_eval_node(n, inst) for n in cfg.get("nodes") or []]
        if not nodes or cfg.get("negate"):
            continue  # a negated configuration describes what is NOT affected; never a match on its own
        values = [n.value for n in nodes]
        value = _and(values) if (cfg.get("operator") or "OR").upper() == "AND" else _or(values)
        if value is None:
            unknown = unknown or _mentions(cfg, inst)
            continue
        if value is not True:
            continue
        hits = [h for n in nodes if n.value is True for h in n.hits]
        if hits:
            # prefer the criterion that names a fixed version
            hits.sort(key=lambda h: (h.fixed_version is None, h.last_affected is None))
            return Verdict("affected", hits[0])
    return Verdict("unknown" if unknown else "not_affected")


def _mentions(cfg: dict[str, Any], inst: Installed) -> bool:
    """Whether an undecided configuration names the installed app as vulnerable (worth counting)."""
    for node in cfg.get("nodes") or []:
        for m in node.get("cpeMatch") or []:
            parts = split_cpe(m.get("criteria", ""))
            if parts and parts[2] == "a" and (parts[3], parts[4]) in inst.cpes and m.get("vulnerable"):
                return True
    return False


# =========================================================================== scores and records


@dataclass
class Score:
    score: float | None
    vector: str | None
    source: str | None
    version: str | None


def pick_score(metrics: dict[str, Any] | None) -> Score:
    """NVD's own CVSS 3.x first, then the CNA's 3.x, then any 4.0 score, then 2.0."""
    metrics = metrics or {}

    def find(key: str, kind: str | None) -> dict[str, Any] | None:
        for entry in metrics.get(key) or []:
            if kind is None or entry.get("type") == kind:
                return entry
        return None

    order: list[tuple[str, str | None]] = [("cvssMetricV31", "Primary"), ("cvssMetricV30", "Primary"),
                                           ("cvssMetricV31", "Secondary"), ("cvssMetricV30", "Secondary"),
                                           ("cvssMetricV40", "Primary"), ("cvssMetricV40", None),
                                           ("cvssMetricV2", "Primary"), ("cvssMetricV2", None)]
    for key, kind in order:
        entry = find(key, kind)
        if entry is None:
            continue
        data = entry.get("cvssData") or {}
        score = data.get("baseScore")
        version = str(data.get("version") or {"cvssMetricV31": "3.1", "cvssMetricV30": "3.0",
                                                 "cvssMetricV40": "4.0", "cvssMetricV2": "2.0"}[key])
        who = "NVD" if entry.get("type") == "Primary" else f"CNA: {entry.get('source') or 'unknown'}"
        label = who if version.startswith("3") else f"{who} (CVSS {version})"
        return Score(float(score) if score is not None else None, data.get("vectorString"), label[:128], version)
    return Score(None, None, None, None)


def english_description(cve: dict[str, Any]) -> str | None:
    for d in cve.get("descriptions") or []:
        if d.get("lang") == "en" and d.get("value"):
            return str(d["value"])
    return None


def compact(cve: dict[str, Any]) -> dict[str, Any]:
    """The parts of a CVE record the matcher and the UI use."""
    desc = english_description(cve)
    return {
        "id": cve.get("id"),
        "sourceIdentifier": cve.get("sourceIdentifier"),
        "vulnStatus": cve.get("vulnStatus"),
        "published": cve.get("published"),
        "lastModified": cve.get("lastModified"),
        "descriptions": [{"lang": "en", "value": desc}] if desc else [],
        "metrics": cve.get("metrics") or {},
        "configurations": cve.get("configurations") or [],
        "references": [r.get("url") for r in (cve.get("references") or []) if r.get("url")][:30],
    }


# =========================================================================== curated Windows apps


VersionFn = Callable[[str, str | None], tuple[str | None, str | None]]


def _display_version(name: str, version: str | None) -> tuple[str | None, str | None]:
    return leading_version(version), None


def _python_version(name: str, version: str | None) -> tuple[str | None, str | None]:
    # The MSI DisplayVersion encodes the release level (3.12.4150.0); the DisplayName has the real one.
    m = re.search(r"Python (\d+\.\d+\.\d+)", name)
    return (m.group(1) if m else None), None


def acrobat_track(version: str | None) -> str | None:
    """Adobe numbers Continuous-track builds YY.MMM.2xxxx and Classic-track builds YY.MMM.3xxxx."""
    m = re.match(r"^\d+\.\d+\.(\d)\d{4}", version or "")
    if not m:
        return None
    return {"2": "continuous", "3": "classic"}.get(m.group(1))


def _java_version(name: str, version: str | None) -> tuple[str | None, str | None]:
    m = re.search(r"\b(\d+) Update (\d+)", name)
    if m:  # Java 8 is named 1.8.0 with update N in NVD
        return f"1.{m.group(1)}.0", f"update{m.group(2)}"
    m = re.search(r"(?:Kit|Environment) (\d+(?:\.\d+){0,2})", name)
    if m:
        return m.group(1), None
    return leading_version(version), None


@dataclass(frozen=True)
class CuratedApp:
    key: str
    label: str
    pattern: re.Pattern[str]
    cpes: tuple[tuple[str, str], ...]
    version_fn: VersionFn = _display_version
    verified: bool = True  # vendor:product checked against NVD data while building this list


def _app(key: str, label: str, pattern: str, cpes: tuple[tuple[str, str], ...], version_fn: VersionFn = _display_version,
         verified: bool = True) -> CuratedApp:
    return CuratedApp(key, label, re.compile(pattern, re.IGNORECASE), cpes, version_fn, verified)


CURATED_APPS: tuple[CuratedApp, ...] = (
    _app("chrome", "Google Chrome", r"^Google Chrome$", (("google", "chrome"),)),
    _app("firefox_esr", "Mozilla Firefox ESR", r"^Mozilla Firefox ESR\b", (("mozilla", "firefox_esr"),), verified=False),
    _app("firefox", "Mozilla Firefox", r"^Mozilla Firefox\b(?! ESR)", (("mozilla", "firefox"),)),
    _app("7zip", "7-Zip", r"^7-Zip\b", (("7-zip", "7-zip"),)),
    _app("vlc", "VLC media player", r"^VLC media player\b", (("videolan", "vlc_media_player"),)),
    _app("git", "Git for Windows", r"^Git(?: version \d[\d.]*)?$",
         (("git-scm", "git"), ("git_for_windows_project", "git_for_windows"))),
    _app("nodejs", "Node.js", r"^Node\.js$", (("nodejs", "node.js"),)),
    _app("python", "Python", r"^Python \d+\.\d+\.\d+ \((?:64|32)-bit\)$", (("python", "python"),), _python_version),
    _app("notepadpp", "Notepad++", r"^Notepad\+\+", (("notepad-plus-plus", "notepad\\+\\+"),)),
    _app("winrar", "WinRAR", r"^WinRAR\b", (("rarlab", "winrar"),)),
    _app("putty", "PuTTY", r"^PuTTY release\b", (("putty", "putty"),)),
    _app("wireshark", "Wireshark", r"^Wireshark\b", (("wireshark", "wireshark"),)),
    _app("filezilla", "FileZilla Client", r"^FileZilla(?: Client)?\b(?!.*Server)",
         (("filezilla-project", "filezilla_client"),)),
    _app("vscode", "Visual Studio Code", r"^Microsoft Visual Studio Code\b", (("microsoft", "visual_studio_code"),)),
    _app("docker_desktop", "Docker Desktop", r"^Docker Desktop$", (("docker", "desktop"),)),
    _app("zoom", "Zoom Workplace", r"^Zoom(?: Workplace)?(?: \((?:64|32)-bit\)|\(64bit\))?$",
         (("zoom", "workplace_desktop"), ("zoom", "zoom"))),
    _app("teamviewer", "TeamViewer", r"^TeamViewer(?: \d+)?(?: \(\w+\))?$", (("teamviewer", "teamviewer"),)),
    _app("acrobat_reader", "Adobe Acrobat Reader", r"^Adobe Acrobat Reader\b",
         (("adobe", "acrobat_reader_dc"), ("adobe", "acrobat_reader"))),
    _app("acrobat", "Adobe Acrobat", r"^Adobe Acrobat(?: DC)?(?: \((?:64|32)-bit\))?$", (("adobe", "acrobat_dc"),)),
    _app("java_jdk", "Oracle Java SE Development Kit", r"^Java(?:\(TM\))? SE Development Kit \d+",
         (("oracle", "jdk"),), _java_version),
    _app("java_jre", "Oracle Java Runtime", r"^Java(?:\(TM\))? (?:\d+ Update \d+|SE Runtime Environment \d+)",
         (("oracle", "jre"),), _java_version),
    _app("openssl", "OpenSSL", r"^OpenSSL\b", (("openssl", "openssl"),)),
)


def match_app(display_name: str | None) -> CuratedApp | None:
    if not display_name:
        return None
    name = display_name.strip()
    for app in CURATED_APPS:
        if app.pattern.search(name):
            return app
    return None


def installed_for(app: CuratedApp, name: str, version: str | None, windows_build: int | None = None) -> Installed | None:
    v, update = app.version_fn(name, version)
    if not v:
        return None
    edition = acrobat_track(v) if app.key.startswith("acrobat") else None
    return Installed(cpes=frozenset(app.cpes), version=v, update=update, sw_edition=edition,
                     windows_build=windows_build)


def product_key(vendor: str, product: str) -> str:
    return f"{vendor}:{product}"


# =========================================================================== fetching


def fetch_product(vendor: str, product: str, api_key: str | None, *, max_wait: float = 0.0,
                  page_wait: float = 35.0, rate: SlidingWindowLimiter | None = None) -> list[dict[str, Any]]:
    """Every CVE NVD links to cpe:2.3:a:<vendor>:<product>, as compact records.

    The first request never waits longer than ``max_wait`` for the rate limiter (``RateLimited`` is
    raised instead, so the caller can try again on a later tick); follow-up pages may wait up to
    ``page_wait`` so a product is not abandoned half-way.
    """
    rate = rate or limiter(bool(api_key))
    match = f"cpe:2.3:a:{vendor}:{product}"
    out: list[dict[str, Any]] = []
    start = 0
    for page in range(100):  # hard stop: 200,000 CVEs for one product would be a bug
        rate.acquire(max_wait if page == 0 else page_wait)
        resp = request(
            "nvd", "GET", API,
            purpose=f"Download known vulnerabilities for {vendor} {product}",
            payload_summary=f"product identifier {match} only (no device data)",
            params={"virtualMatchString": match, "resultsPerPage": PAGE_SIZE, "startIndex": start},
            headers={"apiKey": api_key} if api_key else None,
            timeout=60,
        )
        if resp.status_code != 200:
            raise NvdError(f"NVD returned HTTP {resp.status_code} for {match}")
        try:
            data = resp.json()
        except ValueError as exc:
            raise NvdError(f"NVD returned invalid JSON for {match}") from exc
        batch = [v["cve"] for v in data.get("vulnerabilities") or [] if isinstance(v, dict) and "cve" in v]
        out.extend(compact(c) for c in batch)
        total = int(data.get("totalResults") or 0)
        start += len(batch)
        if not batch or start >= total:
            return out
    raise NvdError(f"NVD paging for {match} did not finish")


__all__ = [
    "CURATED_APPS", "ConfigMatch", "CuratedApp", "Installed", "NvdError", "OutboundError", "RateLimited",
    "SlidingWindowLimiter", "compare_generic", "evaluate", "fetch_product", "has_configurations", "installed_for",
    "limiter", "match_app", "pick_score",
]
