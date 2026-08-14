"""In-memory parent-child process tree and event history.

proc-watch only *observes*; this module never kills, suspends, or
otherwise touches the processes it tracks -- it just keeps bookkeeping
structures that the anomaly rules and the CLI read from.
"""

from __future__ import annotations

import time
from collections import deque
from typing import Any, Deque, Dict, List, Optional


class ProcessTree:
    """Tracks every process we have seen as a node in a tree.

    Data model
    ----------
    ``nodes`` maps pid -> dict with the keys returned by
    ``proc_reader.read_process``.  ``children`` maps pid -> ordered list
    of child pids (order of appearance).

    Because /proc snapshots are taken every poll interval, a very
    short-lived child may already be gone by the time we read it.  If we
    only see the child's entry in /proc/pid/stat but cannot read its
    details, we still record a minimal node so the tree doesn't silently
    lose the parent -> child relationship.
    """

    def __init__(self) -> None:
        self.nodes: Dict[int, Dict[str, Any]] = {}
        self.children: Dict[int, List[int]] = {}
        # ppid -> [child pids that arrived before their parent did].
        self.pending: Dict[int, List[int]] = {}

    def get(self, pid: int) -> Optional[Dict[str, Any]]:
        return self.nodes.get(pid)

    def add(self, record: Dict[str, Any]) -> None:
        """Insert/update a process record and wire up the parent link.

        If a child arrives before its parent (parent was not in the
        previous snapshot), it is parked in ``pending`` and linked the
        moment the parent shows up.  If the parent never appears (already
        exited, or reparented to init) the node stays a forest root.
        """
        pid = record.get("pid")
        if pid is None:
            return
        self.nodes[pid] = record

        ppid = record.get("ppid")
        if ppid is not None and ppid != pid and ppid in self.nodes:
            self._link(ppid, pid)

        # Children that referenced this pid before it appeared.
        if pid in self.pending:
            for child in self.pending.pop(pid):
                if child in self.nodes:
                    self._link(pid, child)

        # Park this node if its parent is not (yet) known.
        if (
            ppid is not None
            and ppid != pid
            and ppid not in self.nodes
        ):
            self.pending.setdefault(ppid, [])
            if pid not in self.pending[ppid]:
                self.pending[ppid].append(pid)

    def _link(self, parent: int, child: int) -> None:
        """Append child under parent's child list (no duplicates)."""
        siblings = self.children.setdefault(parent, [])
        if child not in siblings:
            siblings.append(child)

    def has_pid(self, pid: int) -> bool:
        return pid in self.nodes

    def parent_of(self, pid: int) -> Optional[int]:
        node = self.nodes.get(pid)
        if node is None:
            return None
        ppid = node.get("ppid")
        if ppid is not None and ppid != pid and ppid in self.nodes:
            return int(ppid)
        return None

    def ancestor_chain(self, pid: int) -> List[int]:
        """[pid, parent, grandparent, ...] as far back as we know.

        Stops when the parent is unknown (not in the tree) or on a cycle
        guard (max depth 100) to avoid pathological reparenting loops.
        """
        chain: List[int] = []
        seen: set = set()
        current: Optional[int] = pid
        depth = 0
        while current is not None and current not in seen and depth < 100:
            seen.add(current)
            chain.append(current)
            current = self.parent_of(current)
            depth += 1
        return chain

    def children_of(self, pid: int) -> List[int]:
        return list(self.children.get(pid, []))


class EventHistory:
    """Bounded ring buffer of recent process-creation events.

    Used by the short-lived-burst rule (and the live table) so we don't
    need to retain every event since boot.  ``maxlen=0`` disables the
    buffer entirely.
    """

    def __init__(self, maxlen: int = 5000) -> None:
        self.maxlen = maxlen
        self._events: Deque[Dict[str, Any]] = deque(maxlen=maxlen)

    def add(self, event: Dict[str, Any]) -> None:
        if self.maxlen > 0:
            self._events.append(event)

    def __len__(self) -> int:
        return len(self._events)

    def recent(self, since: Optional[float] = None) -> List[Dict[str, Any]]:
        """Events with ``created_at >= since`` (or all events)."""
        if since is None:
            return list(self._events)
        return [e for e in self._events if e.get("created_at", 0) >= since]

    def clear(self) -> None:
        self._events.clear()

    def as_dicts(self) -> List[Dict[str, Any]]:
        return list(self._events)


class TreeStats:
    """Simple counters exposed to the CLI footer."""

    def __init__(self) -> None:
        self.seen_pids: set = set()
        self.created_at: Dict[int, float] = {}

    def observe(self, record: Dict[str, Any], now: float) -> None:
        pid = record.get("pid")
        if pid is not None:
            self.seen_pids.add(pid)
            self.created_at.setdefault(pid, now)

    def record_event(self, event: Dict[str, Any]) -> None:
        pid = event.get("pid")
        if pid is not None:
            self.created_at[pid] = event.get("created_at") or time.time()

    def uptime_first_seen(self, pid: int) -> Optional[float]:
        created = self.created_at.get(pid)
        if created is None:
            return None
        return time.time() - created