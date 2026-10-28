"""The process tree is the engine's memory; if lineage is wrong, every correlation built on it is wrong."""

from __future__ import annotations

from sentinel_detect import ProcessTree, StreamBuilder


def _tree(events) -> ProcessTree:
    tree = ProcessTree()
    for event in events:
        tree.ingest(event)
    return tree


def test_create_is_recorded_and_retrievable_by_guid():
    b = StreamBuilder()
    b.process_create("A", r"C:\Windows\System32\cmd.exe", pid=42, command_line="cmd /c whoami", user="alice")
    tree = _tree(b.events)
    node = tree.get("A")
    assert node is not None
    assert node.pid == 42
    assert node.image_name == "cmd.exe"
    assert node.command_line == "cmd /c whoami"
    assert node.user == "alice"
    assert node.exited is False


def test_ancestry_walks_parents_nearest_first_and_stops_at_unknown():
    b = StreamBuilder()
    b.process_create("root", r"C:\Windows\explorer.exe")
    b.process_create("mid", r"C:\Windows\System32\cmd.exe", parent_guid="root")
    b.process_create("leaf", r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe", parent_guid="mid")
    tree = _tree(b.events)
    chain = [n.process_guid for n in tree.ancestry("leaf")]
    assert chain == ["leaf", "mid", "root"]
    # a process whose parent was never observed simply yields itself
    b2 = StreamBuilder()
    b2.process_create("orphan", r"C:\x.exe", parent_guid="never-seen")
    assert [n.process_guid for n in _tree(b2.events).ancestry("orphan")] == ["orphan"]


def test_ancestry_tolerates_a_cycle():
    # Pathological input (a parent pointing back into its own descendants) must not loop forever.
    b = StreamBuilder()
    b.process_create("x", r"C:\x.exe", parent_guid="y")
    b.process_create("y", r"C:\y.exe", parent_guid="x")
    chain = [n.process_guid for n in _tree(b.events).ancestry("x")]
    assert chain == ["x", "y"]  # each guid visited at most once


def test_non_create_event_synthesizes_a_stub():
    # The collector can start mid-stream; an action from an unseen process should still resolve.
    b = StreamBuilder()
    b.network_connect("ghost", "8.8.8.8", 443, image=r"C:\mystery.exe")
    tree = _tree(b.events)
    node = tree.get("ghost")
    assert node is not None and node.synthesized is True
    assert node.image_name == "mystery.exe"


def test_process_exit_marks_but_keeps_the_node():
    b = StreamBuilder()
    b.process_create("A", r"C:\cmd.exe", pid=7)
    b.process_exit("A", pid=7)
    node = _tree(b.events).get("A")
    assert node is not None and node.exited is True and node.exit_ts is not None


def test_eviction_drops_exited_before_live():
    tree = ProcessTree(max_nodes=3)
    b = StreamBuilder()
    # three processes; the first two exit, the third stays live
    b.process_create("gone1", r"C:\a.exe")
    b.process_exit("gone1")
    b.process_create("gone2", r"C:\b.exe")
    b.process_exit("gone2")
    b.process_create("live", r"C:\c.exe")
    for event in b.events:
        tree.ingest(event)
    # now add two more live processes, forcing eviction past the cap
    b2 = StreamBuilder()
    b2.process_create("live2", r"C:\d.exe")
    b2.process_create("live3", r"C:\e.exe")
    for event in b2.events:
        tree.ingest(event)
    assert tree.get("live") is not None  # live lineage preserved
    assert tree.get("gone1") is None and tree.get("gone2") is None  # exited evicted first
    assert len(tree) <= 3


def test_snapshot_returns_ancestry_as_process_snapshots():
    b = StreamBuilder()
    b.process_create("root", r"C:\Windows\explorer.exe")
    b.process_create("child", r"C:\cmd.exe", parent_guid="root")
    snaps = _tree(b.events).snapshot("child")
    assert [s.process_guid for s in snaps] == ["child", "root"]
    assert snaps[0].image == r"C:\cmd.exe"
