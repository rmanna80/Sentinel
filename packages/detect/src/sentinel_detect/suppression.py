"""Suppression: the first, bluntest answer to the hardest problem in detection.

Every pattern a rule looks for is also something legitimate administration does. The only way a behavioural
engine is usable is if it can be told "this exact thing, from this exact tool, is expected here." That is
suppression. It is applied *after* a rule fires, so suppressing one benign source never blinds the rule to
the same behaviour from somewhere else.

This is intentionally simple — glob matches on image paths, scoped to a rule. It is not a baseline engine or
an ML model; it is the allowlist you grow as you learn your own environment. Keeping it explicit and readable
matters more than keeping it clever: every entry is a documented decision to stop looking at something.
"""

from __future__ import annotations

from fnmatch import fnmatch

from pydantic import BaseModel, Field, model_validator
from sentinel_core.telemetry import Detection


class Suppression(BaseModel):
    reason: str = Field(max_length=500)  # why this is expected; every entry must justify itself
    rule_id: str | None = Field(default=None, max_length=128)  # None: applies to every rule
    image: str | None = Field(default=None, max_length=1024)  # glob vs. a triggering process image or parent
    path_prefix: str | None = Field(default=None, max_length=1024)  # suppress if a triggering image lives here

    @model_validator(mode="after")
    def _needs_a_subject(self) -> Suppression:
        if not (self.image or self.path_prefix):
            raise ValueError("a suppression must constrain by image or path_prefix")
        return self

    def matches(self, detection: Detection) -> bool:
        if self.rule_id is not None and self.rule_id != detection.rule_id:
            return False
        images = _images(detection)
        if self.image is not None and any(_glob(self.image, img) for img in images):
            return True
        if self.path_prefix is not None:
            prefix = _norm(self.path_prefix)
            return any(_norm(img).startswith(prefix) for img in images)
        return False


class SuppressionList:
    def __init__(self, suppressions: list[Suppression] | None = None) -> None:
        self._items = list(suppressions or [])

    def suppresses(self, detection: Detection) -> Suppression | None:
        """Return the first suppression that explains this detection away, or None to let it through."""
        for item in self._items:
            if item.matches(detection):
                return item
        return None


def _images(detection: Detection) -> list[str]:
    out: list[str] = []
    for event in detection.events:
        if event.image:
            out.append(event.image)
        if event.parent_image:
            out.append(event.parent_image)
    return out


def _norm(path: str) -> str:
    return path.replace("\\", "/").lower()


def _glob(pattern: str, path: str) -> bool:
    # Case-insensitive, slash-insensitive. A pattern with no separator is matched against the base name too,
    # so "powershell.exe" suppresses it wherever it lives, while "C:\\Program Files\\X\\*" is path-scoped.
    npat, npath = _norm(pattern), _norm(path)
    if fnmatch(npath, npat):
        return True
    if "/" not in npat:
        return fnmatch(npath.rsplit("/", 1)[-1], npat)
    return False


def default_suppressions() -> SuppressionList:
    """A deliberately tiny starter list. Real environments grow their own; these are illustrative.

    Note what is *not* here: no blanket "ignore powershell" entry. Suppression is per-source, never
    per-behaviour — we stop trusting a path, not a whole class of activity.
    """
    return SuppressionList([
        Suppression(
            reason="Sentinel's own protected agent runs read-only checks that can look shell-like",
            path_prefix="C:\\Program Files\\Sentinel\\",
        ),
    ])
