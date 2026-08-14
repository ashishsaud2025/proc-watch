"""Unit tests for every anomaly rule + the engine wrapper.

Synthetic records only -- no /proc access -- so these pass identically
on any machine and in CI.
"""

from __future__ import annotations

import pytest

import rules
from conftest import make_record

# check_unusual_parent

class TestUnusualParent:
    def test_flags_shell_spawned_by_webserver(self, parent_record):
        child = make_record(pid=501, ppid=500, name="bash", exe="/usr/bin/bash")
        pairs = [
            {"parent": "nginx", "child": "bash|sh"},
            {"parent": "httpd", "child": "bash|sh"},
        ]
        flags = rules.check_unusual_parent(child, parent_record, pairs)
        assert len(flags) == 1
        assert flags[0]["id"] == "unusual_parent"
        assert flags[0]["severity"] == rules.SEVERITY_HIGH
        assert "bash" in flags[0]["summary"]
        assert "heuristic" in flags[0]["description"].lower()

    def test_no_flag_for_normal_parent(self, proc, parent_record):
        child = make_record(pid=501, ppid=500, name="sleep", exe="/usr/bin/sleep")
        pairs = [{"parent": "nginx", "child": "bash|sh"}]
        assert rules.check_unusual_parent(child, parent_record, pairs) == []

    def test_no_flag_when_parent_missing(self):
        child = make_record(pid=501, ppid=999, name="bash", exe="/usr/bin/bash")
        pairs = [{"parent": "nginx", "child": "bash|sh"}]
        assert rules.check_unusual_parent(child, None, pairs) == []

    def test_pipe_alternation_matches_dash(self, parent_record):
        child = make_record(pid=501, ppid=500, name="dash", exe="/usr/bin/dash")
        pairs = [{"parent": "nginx", "child": "bash|sh|dash"}]
        flags = rules.check_unusual_parent(child, parent_record, pairs)
        assert len(flags) == 1

    def test_empty_pairs_never_flag(self, parent_record):
        child = make_record(pid=501, ppid=500, name="bash", exe="/usr/bin/bash")
        assert rules.check_unusual_parent(child, parent_record, []) == []

    def test_glob_parent_pattern(self):
        child = make_record(pid=9, ppid=8, name="sh", exe="/bin/sh")
        parent = make_record(pid=8, ppid=1, name="libreoffice", exe="/usr/bin/libreoffice")
        pairs = [{"parent": "libreoffice*", "child": "sh|cmd"}]
        flags = rules.check_unusual_parent(child, parent, pairs)
        assert len(flags) == 1


# check_unusual_location

class TestUnusualLocation:
    def test_flags_tmp_executable(self):
        rec = make_record(
            pid=1,
            ppid=0,
            name="evil",
            exe="/tmp/evil.sh",
        )
        flags = rules.check_unusual_location(rec, ["/tmp", "/dev/shm", "/var/tmp"])
        assert len(flags) == 1
        assert flags[0]["id"] == "unusual_location"
        assert "running from" in flags[0]["summary"]
        assert "heuristic" in flags[0]["description"].lower()

    def test_flags_nested_tmp_path(self):
        rec = make_record(pid=2, ppid=1, name="x", exe="/tmp/payload/app")
        flags = rules.check_unusual_location(rec, ["/tmp"])
        assert len(flags) == 1

    def test_no_flag_for_system_binary(self):
        rec = make_record(pid=3, ppid=1, name="bash", exe="/usr/bin/bash")
        assert rules.check_unusual_location(rec, ["/tmp", "/dev/shm"]) == []

    def test_no_flag_for_missing_exe(self):
        rec = {
            "pid": 4,
            "ppid": 1,
            "exe": None,
            "cmdline": [],
            "comm": "kthreadd",
        }
        assert rules.check_unusual_location(rec, ["/tmp"]) == []

    def test_no_flag_when_dir_list_empty(self):
        rec = make_record(pid=5, ppid=1, name="evil", exe="/tmp/evil")
        assert rules.check_unusual_location(rec, []) == []

    def test_no_flag_for_similar_tmp_like_dir(self):
        # /tmp2 is not /tmp; must not be flagged (avoids prefix false positive)
        rec = make_record(pid=6, ppid=1, name="x", exe="/tmp2/app")
        assert rules.check_unusual_location(rec, ["/tmp"]) == []


# check_typosquat

class TestTypo:
    KNOWN = ["systemd", "sshd", "bash", "sh", "nginx"]

    def test_flags_systemdd(self):
        rec = make_record(pid=1, ppid=1, name="systemdd", exe="/usr/bin/systemdd")
        flags = rules.check_typosquat(rec, self.KNOWN)
        assert len(flags) == 1
        assert flags[0]["id"] == "typosquat"
        assert "systemd" in flags[0]["summary"]

    def test_flags_ssdh(self):
        rec = make_record(pid=2, ppid=1, name="ssdh", exe="/usr/sbin/ssdh")
        flags = rules.check_typosquat(rec, self.KNOWN)
        assert len(flags) >= 1

    def test_no_flag_for_exact_match(self):
        rec = make_record(pid=3, ppid=1, name="systemd", exe="/usr/lib/systemd")
        assert rules.check_typosquat(rec, self.KNOWN) == []

    def test_no_flag_far_name(self):
        rec = make_record(pid=4, ppid=1, name="myapp", exe="/usr/bin/myapp")
        assert rules.check_typosquat(rec, self.KNOWN) == []

    def test_max_distance_zero_disables(self):
        rec = make_record(pid=5, ppid=1, name="systemdd", exe="/usr/bin/systemdd")
        assert rules.check_typosquat(rec, self.KNOWN, max_edit_distance=0) == []

    def test_distance_two_matches_when_permitted(self):
        rec = make_record(pid=6, ppid=1, name="ssdhd", exe="/usr/sbin/ssdhd")
        assert rules.check_typosquat(rec, self.KNOWN, max_edit_distance=2) != []

    def test_multiple_close_knowns_all_flagged(self):
        # "bashh" is edit-distance-1 from "bash" only in this list
        rec = make_record(pid=7, ppid=1, name="bashh", exe="/usr/bin/bashh")
        flags = rules.check_typosquat(rec, self.KNOWN)
        ids = {f["id"] for f in flags}
        assert ids == {"typosquat"}


# check_burst

class TestBurst:
    def test_flags_burst_above_threshold(self):
        now = 2000.0
        rec = make_record(pid=6, ppid=10, name="child", exe="/bin/child")
        recent = [
            {"pid": 1, "ppid": 10, "created_at": now - 0.5},
            {"pid": 2, "ppid": 10, "created_at": now - 1.0},
            {"pid": 3, "ppid": 10, "created_at": now - 1.5},
            {"pid": 4, "ppid": 10, "created_at": now - 2.0},
            {"pid": 5, "ppid": 10, "created_at": now - 2.5},
        ]
        flags = rules.check_burst(rec, recent, window_seconds=5.0, threshold=5, now=now)
        assert len(flags) == 1
        assert flags[0]["id"] == "burst"
        # 5 prior + current = 6 total
        assert "6" in flags[0]["summary"]

    def test_no_flag_below_threshold(self):
        now = 3000.0
        rec = make_record(pid=3, ppid=10, name="child", exe="/bin/child")
        recent = [
            {"pid": 1, "ppid": 10, "created_at": now - 0.5},
            {"pid": 2, "ppid": 10, "created_at": now - 1.0},
        ]
        assert rules.check_burst(rec, recent, window_seconds=5.0, threshold=5, now=now) == []

    def test_no_flag_other_parents(self):
        now = 4000.0
        rec = make_record(pid=3, ppid=10, name="child", exe="/bin/child")
        recent = [
            {"pid": 1, "ppid": 99, "created_at": now - 0.5},
            {"pid": 2, "ppid": 99, "created_at": now - 1.0},
        ]
        assert rules.check_burst(rec, recent, window_seconds=5.0, threshold=2, now=now) == []

    def test_stale_events_excluded_by_window(self):
        now = 5000.0
        rec = make_record(pid=6, ppid=10, name="child", exe="/bin/child")
        recent = [
            {"pid": 1, "ppid": 10, "created_at": now - 60.0},
            {"pid": 2, "ppid": 10, "created_at": now - 59.0},
            {"pid": 3, "ppid": 10, "created_at": now - 58.0},
            {"pid": 4, "ppid": 10, "created_at": now - 57.0},
            {"pid": 5, "ppid": 10, "created_at": now - 56.0},
        ]
        assert rules.check_burst(rec, recent, window_seconds=5.0, threshold=5, now=now) == []

    def test_missing_ppid_never_flags(self):
        rec = {"pid": 9, "ppid": None, "name": "kid"}
        assert rules.check_burst(rec, [], window_seconds=5.0, threshold=1, now=100.0) == []

    def test_zero_threshold_disables(self):
        now = 6000.0
        rec = make_record(pid=1, ppid=10, name="x", exe="/bin/x")
        recent = [{"pid": 0, "ppid": 10, "created_at": now - 0.1}]
        assert rules.check_burst(rec, recent, window_seconds=5.0, threshold=0, now=now) == []


# AnomalyEngine (integration of all rules)

class TestEngine:
    def _make_config(self) -> dict:
        return {
            "unusual_parent_child_pairs": [
                {"parent": "nginx", "child": "bash|sh"}
            ],
            "world_writable_dirs": ["/tmp", "/dev/shm"],
            "known_binaries": ["systemd", "sshd", "bash"],
            "typosquat_max_edit_distance": 1,
            "burst_window_seconds": 5.0,
            "burst_threshold": 5,
        }

    def _dummy_tree(self) -> object:
        class DummyTree:
            def __init__(self, nodes: dict):
                self.nodes = nodes

            def get(self, pid):
                return self.nodes.get(pid)

        return DummyTree

    def _dummy_history(self, events):
        class DummyHistory:
            def recent(self, since):
                return events

        return DummyHistory()

    def test_engine_flags_multiple_rules(self):
        now = 7000.0
        parent = make_record(pid=500, ppid=1, name="nginx", exe="/usr/sbin/nginx")
        child = make_record(pid=501, ppid=500, name="systemdd", exe="/tmp/systemdd")
        recent = [
            {"pid": i, "ppid": 500, "created_at": now - 0.1 * i} for i in range(6)
        ]
        tree = self._dummy_tree()({500: parent})
        history = self._dummy_history(recent)
        engine = rules.AnomalyEngine(self._make_config())
        flags = engine.evaluate(child, tree, history, now=now)

        ids = {f["id"] for f in flags}
        # unusual parent (nginx -> ???) requires "bash|sh|cmd" child, not met;
        # unusual location from /tmp; typo vs systemd; burst (6 prior + 1)
        assert "unusual_location" in ids
        assert "typosquat" in ids
        # parent rule: child is systemdd, not a shell -> not flagged
        assert "unusual_parent" not in ids
        # burst: 6 events for ppid 500 + current = 7 >= threshold 5
        assert "burst" in ids

        for f in flags:
            assert f.get("pid") == 501
            assert f.get("ppid") == 500
            assert f.get("process_name") == "systemdd"

    def test_engine_flags_unusual_parent(self):
        now = 8000.0
        parent = make_record(pid=500, ppid=1, name="nginx", exe="/usr/sbin/nginx")
        child = make_record(pid=502, ppid=500, name="sh", exe="/bin/sh")
        tree = self._dummy_tree()({500: parent})
        engine = rules.AnomalyEngine(self._make_config())
        flags = engine.evaluate(child, tree, self._dummy_history([]), now=now)
        ids = {f["id"] for f in flags}
        assert "unusual_parent" in ids

    def test_engine_flags_get_decorated_fields(self):
        parent = make_record(pid=500, ppid=1, name="nginx", exe="/usr/sbin/nginx")
        child = make_record(
            pid=503,
            ppid=500,
            name="ssdh",
            exe="/tmp/ssdh",
            cmdline=["/tmp/ssdh", "-p", "22"],
            user="bob",
        )
        tree = self._dummy_tree()({500: parent})
        engine = rules.AnomalyEngine(self._make_config())
        flags = engine.evaluate(child, tree, self._dummy_history([]), now=9000.0)
        assert flags, "expected at least one flag"
        for f in flags:
            assert f["pid"] == 503
            assert f["ppid"] == 500
            assert f["process_name"] == "ssdh"
            assert f["user"] == "bob"
            assert f["cmdline"] == ["/tmp/ssdh", "-p", "22"]