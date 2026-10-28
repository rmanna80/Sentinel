"""The process tree: the memory the detection engine keeps about what is running.

Almost every interesting behaviour is a *relationship* between processes — "a document opened a shell",
"that shell's child reached the internet". To see those you need lineage, and lineage means remembering
every process creation and tying children to parents. This module is that memory.

Processes are keyed by GUID, never PID. Windows reuses a PID within seconds of a process exiting, so a PID
is ambiguous the moment you store it; a GUID is unique for the life of the machine. Exited processes are
kept (marked exited) rather than deleted, because events about a process can still arrive just after it dies
and because a detection needs to describe ancestry that may already be gone. The store is bounded: once it
is full, the oldest exited processes are evicted first so that live lineage is preserved.
"""

from __future__ import annotations

from collections import OrderedDict
from dataclasses import dataclass
from datetime import datetime

from sentinel_core.telemetry import EventKind, ProcessSnapshot, TelemetryEvent


@dataclass
class ProcessNode:
    process_guid: str
    pid: int
    image: str = ""
    command_line: str | None = None
    user: str | None = None
    parent_guid: str | None = None
    parent_image: str | None = None
    start_ts: datetime | None = None
    exited: bool = False
    exit_ts: datetime | None = None
    synthesized: bool = False  # inferred from a non-create event, not from an observed creation

    @property
    def image_name(self) -> str:
        """The executable's base name, lower-cased (``C:\\Windows\\System32\\cmd.exe`` -> ``cmd.exe``)."""
        return _basename(self.image)

    def snapshot(self) -> ProcessSnapshot:
        return ProcessSnapshot(
            process_guid=self.process_guid, pid=self.pid, image=self.image,
            command_line=self.command_line, user=self.user, parent_guid=self.parent_guid,
        )


def _basename(path: str | None) -> str:
    if not path:
        return ""
    # Windows paths use backslashes; be tolerant of forward slashes too.
    tail = path.replace("\\", "/").rsplit("/", 1)[-1]
    return tail.lower()


class ProcessTree:
    def __init__(self, max_nodes: int = 200_000) -> None:
        self.max_nodes = max_nodes
        self._nodes: OrderedDict[str, ProcessNode] = OrderedDict()  # insertion order drives eviction

    def __len__(self) -> int:
        return len(self._nodes)

    def ingest(self, event: TelemetryEvent) -> ProcessNode:
        """Update the tree from one event and return the acting process's node.

        A ``process_create`` records a real node. Any other event whose process we have never seen records a
        *synthesized* stub (the collector may have started mid-stream), so the acting process is always
        resolvable even when its creation was missed.
        """
        if event.kind is EventKind.PROCESS_CREATE:
            return self._put(ProcessNode(
                process_guid=event.process_guid, pid=event.pid, image=event.image,
                command_line=event.command_line, user=event.user,
                parent_guid=event.parent_guid, parent_image=event.parent_image, start_ts=event.ts,
            ))

        node = self._nodes.get(event.process_guid)
        if node is None:
            node = self._put(ProcessNode(
                process_guid=event.process_guid, pid=event.pid, image=event.image,
                user=event.user, start_ts=event.ts, synthesized=True,
            ))
        if event.kind is EventKind.PROCESS_EXIT:
            node.exited = True
            node.exit_ts = event.ts
        return node

    def _put(self, node: ProcessNode) -> ProcessNode:
        # A repeated create for the same GUID (should not happen) just refreshes the existing node.
        self._nodes.pop(node.process_guid, None)
        self._nodes[node.process_guid] = node
        self._evict_if_needed()
        return node

    def _evict_if_needed(self) -> None:
        if len(self._nodes) <= self.max_nodes:
            return
        over = len(self._nodes) - self.max_nodes
        # First pass: drop the oldest *exited* processes. Live lineage is never evicted to make room.
        for guid in list(self._nodes):
            if over <= 0:
                break
            if self._nodes[guid].exited:
                del self._nodes[guid]
                over -= 1
        # If still over (an implausible number of live processes), drop the oldest regardless.
        while over > 0 and self._nodes:
            self._nodes.popitem(last=False)
            over -= 1

    def get(self, guid: str | None) -> ProcessNode | None:
        return self._nodes.get(guid) if guid else None

    def ancestry(self, guid: str | None, max_depth: int = 24) -> list[ProcessNode]:
        """The acting process followed by its ancestors, nearest first. Stops at an unknown parent or a cycle."""
        chain: list[ProcessNode] = []
        seen: set[str] = set()
        current = self.get(guid)
        while current is not None and current.process_guid not in seen and len(chain) < max_depth:
            chain.append(current)
            seen.add(current.process_guid)
            current = self.get(current.parent_guid)
        return chain

    def snapshot(self, guid: str | None) -> list[ProcessSnapshot]:
        return [node.snapshot() for node in self.ancestry(guid)]
