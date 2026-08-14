"""Unit tests for ProcessTree, EventHistory, and TreeStats.

All synthetic -- no /proc access.
"""

from __future__ import annotations

from tree import EventHistory, ProcessTree, TreeStats
from conftest import make_record


class TestProcessTree:
    def test_add_and_get(self):
        tree = ProcessTree()
        rec = make_record(pid=100, ppid=1, name="app", exe="/usr/bin/app")
        tree.add(rec)
        assert tree.get(100) is rec

    def test_links_child_to_parent(self):
        tree = ProcessTree()
        parent = make_record(pid=10, ppid=1, name="bash", exe="/usr/bin/bash")
        child = make_record(pid=11, ppid=10, name="ls", exe="/usr/bin/ls")
        tree.add(parent)
        tree.add(child)
        assert tree.children_of(10) == [11]
        assert tree.parent_of(11) == 10
        assert tree.parent_of(10) is None  # pid 1 not in the tree yet

    def test_no_self_link(self):
        tree = ProcessTree()
        rec = make_record(pid=42, ppid=42, name="weird", exe="/usr/bin/weird")
        tree.add(rec)
        assert tree.children_of(42) == []
        assert tree.parent_of(42) is None

    def test_links_when_child_arrives_before_parent(self):
        tree = ProcessTree()
        child = make_record(pid=11, ppid=10, name="ls", exe="/usr/bin/ls")
        tree.add(child)
        assert tree.parent_of(11) is None  # parent unknown for now
        parent = make_record(pid=10, ppid=1, name="bash", exe="/usr/bin/bash")
        tree.add(parent)
        # Delayed link is now wired up.
        assert tree.children_of(10) == [11]
        assert tree.parent_of(11) == 10

    def test_no_duplicate_children(self):
        tree = ProcessTree()
        parent = make_record(pid=10, ppid=1, name="bash", exe="/usr/bin/bash")
        child = make_record(pid=11, ppid=10, name="ls", exe="/usr/bin/ls")
        tree.add(parent)
        tree.add(child)
        tree.add(child)  # duplicate update
        assert tree.children_of(10) == [11]

    def test_ancestor_chain(self):
        tree = ProcessTree()
        a = make_record(pid=1, ppid=0, name="init", exe="/sbin/init")
        b = make_record(pid=2, ppid=1, name="systemd", exe="/lib/systemd")
        c = make_record(pid=3, ppid=2, name="sshd", exe="/usr/sbin/sshd")
        tree.add(a)
        tree.add(b)
        tree.add(c)
        assert tree.ancestor_chain(3) == [3, 2, 1]

    def test_ancestor_chain_stops_at_unknown_parent(self):
        tree = ProcessTree()
        child = make_record(pid=3, ppid=999, name="orphan", exe="/usr/bin/orphan")
        tree.add(child)
        assert tree.ancestor_chain(3) == [3]

    def test_ancestor_chain_cycle_guard(self):
        tree = ProcessTree()
        x = make_record(pid=1, ppid=2, name="x", exe="/usr/bin/x")
        y = make_record(pid=2, ppid=1, name="y", exe="/usr/bin/y")
        tree.add(x)
        tree.add(y)
        chain = tree.ancestor_chain(1)
        # Must terminate even with a ppid cycle.
        assert len(chain) <= 100


class TestEventHistory:
    def test_add_and_len(self):
        h = EventHistory(maxlen=100)
        h.add({"pid": 1})
        h.add({"pid": 2})
        assert len(h) == 2

    def test_maxlen_evicts_oldest(self):
        h = EventHistory(maxlen=3)
        for pid in (1, 2, 3, 4):
            h.add({"pid": pid, "created_at": float(pid)})
        assert len(h) == 3
        assert h.as_dicts()[0]["pid"] == 2

    def test_maxlen_zero_disables(self):
        h = EventHistory(maxlen=0)
        h.add({"pid": 1})
        assert len(h) == 0

    def test_recent_filters_by_timestamp(self):
        h = EventHistory()
        h.add({"pid": 1, "created_at": 10.0})
        h.add({"pid": 2, "created_at": 20.0})
        h.add({"pid": 3, "created_at": 30.0})
        assert [e["pid"] for e in h.recent(since=20.0)] == [2, 3]
        assert [e["pid"] for e in h.recent()] == [1, 2, 3]

    def test_clear(self):
        h = EventHistory()
        h.add({"pid": 1})
        h.clear()
        assert len(h) == 0


class TestTreeStats:
    def test_observe_tracks_first_seen(self):
        stats = TreeStats()
        rec = make_record(pid=5, ppid=1, name="x", exe="/usr/bin/x")
        stats.observe(rec, now=1000.0)
        stats.observe(rec, now=1005.0)
        assert stats.seen_pids == {5}
        assert stats.created_at[5] == 1000.0

    def test_uptime_first_seen(self, monkeypatch):
        stats = TreeStats()
        rec = make_record(pid=7, ppid=1, name="y", exe="/usr/bin/y")
        monkeypatch.setattr("tree.time.time", lambda: 2000.0)
        stats.observe(rec, now=1990.0)
        assert stats.uptime_first_seen(7) == 10.0