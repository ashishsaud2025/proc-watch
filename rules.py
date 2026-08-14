"""Anomaly heuristics for proc-watch.

Every rule is a pure-ish function that takes a synthetic process record
(dict) and returns a list of flag dicts.  They never touch /proc and
never act on processes -- they only compute booleans on the data they
are handed, which is what makes them unit-testable in CI.

IMPORTANT: everything here is a *heuristic*, not ground truth.  The
descriptions attached to each flag say so explicitly, because a
legitimate developer workflow (running scripts from /tmp, spawning a
shell from a browser, etc.) can easily trip these rules.
"""

from __future__ import annotations

import fnmatch
import os
from typing import Any, Dict, List, Optional, Sequence

# Severity levels used by the CLI for colouring.
SEVERITY_HIGH = "high"
SEVERITY_MEDIUM = "medium"
SEVERITY_LOW = "low"


def _distance(a: str, b: str) -> int:
    """Damerau-Levenshtein edit distance (OSA variant).

    Like Levenshtein but also treats an adjacent transposition (e.g.
    'sshd' -> 'ssdh') as a single edit.  This makes the typosquat rule
    catch the classic swap-a-letter pattern at distance 1 instead of 2.
    Iterative, O(len(a)*len(b)) time and O(len(b)) space.
    """
    if a == b:
        return 0
    if not a:
        return len(b)
    if not b:
        return len(a)
    # Rolling rows: d_prev2 = d[i-2], d_prev1 = d[i-1], cur = d[i].
    # The transposition term needs d[i-2][j-2], hence the extra row.
    d_prev2: Optional[List[int]] = None
    d_prev1 = list(range(len(b) + 1))  # row 0
    for i, ca in enumerate(a, start=1):
        cur = [0] * (len(b) + 1)
        cur[0] = i
        for j, cb in enumerate(b, start=1):
            cost = 0 if ca == cb else 1
            best = min(
                cur[j - 1] + 1,              # deletion
                d_prev1[j] + 1,              # insertion
                d_prev1[j - 1] + cost,       # substitution
            )
            # Adjacent transposition: a[i-1]==b[j-2] and a[i-2]==b[j-1].
            if (
                i > 1
                and j > 1
                and d_prev2 is not None
                and ca == b[j - 2]
                and a[i - 2] == cb
            ):
                best = min(best, d_prev2[j - 2] + 1)
            cur[j] = best
        d_prev2, d_prev1 = d_prev1, cur
    return d_prev1[-1]


def _process_name(record: Dict[str, Any]) -> Optional[str]:
    """Best-effort process name: basename(exe), falling back to comm."""
    name = record.get("name")
    if name:
        return name
    exe = record.get("exe")
    if exe:
        base = os.path.basename(exe)
        if base:
            return base
    return record.get("comm")


def _make_flag(
    rule_id: str,
    severity: str,
    summary: str,
    description: str,
    confidence: Optional[float] = None,
) -> Dict[str, Any]:
    flag: Dict[str, Any] = {
        "id": rule_id,
        "severity": severity,
        "summary": summary,
        "description": description,
    }
    if confidence is not None:
        flag["confidence"] = confidence
    return flag


# Rule 1: "Living off the land" -- unusual parent -> child spawn

def _pattern_alternatives(pattern: str) -> List[str]:
    """Split a pattern on '|' into alternatives, trimmed of spaces.

    proc-watch extends plain fnmatch with ``|`` alternation so configs
    can express ``"bash|sh|dash"`` compactly.  A pattern with no '|'
    simply yields itself.
    """
    return [alt.strip() for alt in pattern.split("|") if alt.strip()]


def _matches_any(name: str, pattern: Optional[str]) -> bool:
    """fnmatch against any '|' alternative of ``pattern``."""
    if not name or not pattern:
        return False
    return any(fnmatch.fnmatch(name, alt) for alt in _pattern_alternatives(pattern))


def check_unusual_parent(
    record: Dict[str, Any],
    parent: Optional[Dict[str, Any]],
    unusual_pairs: Sequence[Dict[str, str]],
) -> List[Dict[str, Any]]:
    """Flag when a child process matches a configured "suspicious
    descendant" pattern of its known parent.

    ``unusual_pairs`` is a list of ``{"parent": <fnmatch pattern>,
    "child": <fnmatch pattern>}``.  Both patterns may contain ``|``
    alternation (e.g. ``"bash|sh"``).  Patterns match on *process name*
    (basename of the executable).

    Heuristic: on a stock Linux system, nginx/httpd never spawn shells,
    and Office-like apps never spawn cmd/powershell.  When one does, it
    is a classic "living off the land" signal -- but note that a web app
    that legitimately shells out to run a CGI script will trip this.
    """
    if not record or not unusual_pairs:
        return []
    child_name = _process_name(record)
    if not child_name:
        return []
    parent_name = _process_name(parent) if parent else None

    flags: List[Dict[str, Any]] = []
    for pair in unusual_pairs:
        parent_pat = pair.get("parent", "")
        child_pat = pair.get("child", "")
        if not child_pat:
            continue
        parent_matches = parent_name and _matches_any(parent_name, parent_pat)
        child_matches = _matches_any(child_name, child_pat)
        if child_matches and parent_matches:
            flags.append(
                _make_flag(
                    "unusual_parent",
                    SEVERITY_HIGH,
                    f"{child_name} spawned by {parent_name}",
                    (
                        f"Heuristic: '{child_name}' was spawned by a parent "
                        f"('{parent_name}') that is not expected to launch this kind "
                        f"of child on this system (configured pair: "
                        f"'{parent_pat}' -> '{child_pat}'). "
                        f"This is a pattern commonly seen in 'living off the land' "
                        f"attacks, but it is NOT ground truth -- a legitimately "
                        f"integrated web app shelling out for CGI would match too."
                    ),
                )
            )
    return flags


# Rule 2: Executable in a world-writable location

def check_unusual_location(
    record: Dict[str, Any],
    world_writable_dirs: Sequence[str],
) -> List[Dict[str, Any]]:
    """Flag when the executable path lives under a world-writable dir.

    Heuristic: attackers drop payloads in /tmp, /dev/shm, /var/tmp, etc.
    because anyone can write there.  However, tons of legitimate software
    (pip installs, dev tooling, cron jobs, build scripts) runs from /tmp
    or ~/.cache -- so treat this as a hint to *look* at the process, not
    as a verdict.
    """
    if not record or not world_writable_dirs:
        return []
    exe = record.get("exe")
    if not exe:
        return []
    exe_norm = os.path.normpath(exe)
    name = _process_name(record) or exe

    for d in world_writable_dirs:
        if not d:
            continue
        d_norm = os.path.normpath(d)
        if exe_norm == d_norm or exe_norm.startswith(d_norm + os.sep):
            return [
                _make_flag(
                    "unusual_location",
                    SEVERITY_MEDIUM,
                    f"{name} running from {d}",
                    (
                        f"Heuristic: '{exe}' lives under the world-writable "
                        f"directory '{d}'.  Malware frequently hides payloads "
                        f"there, but so do legit scripts (e.g. 'pip install --user', "
                        f"dev tooling, cron jobs).  This is a signal to investigate, "
                        f"not a verdict."
                    ),
                )
            ]
    return []


# Rule 3: Typosquatting / masquerading binary names

def check_typosquat(
    record: Dict[str, Any],
    known_binaries: Sequence[str],
    max_edit_distance: int = 1,
) -> List[Dict[str, Any]]:
    """Flag when a process name is *close but not identical* to a known
    system binary, e.g. 'systemdd' vs 'systemd', 'ssdh' vs 'sshd'.

    Heuristic: attackers name their implants one letter off from a real
    binary to blend in with process listings.  The edit distance is a
    cheap approximation of "looks like"; it will also match innocent
    names (e.g. 'shhd' from a typo-ridden dev box) -- hence the
    'not ground truth' wording.
    """
    if not record or not known_binaries:
        return []
    name = _process_name(record)
    if not name:
        return []

    flags: List[Dict[str, Any]] = []
    for known in known_binaries:
        if not known:
            continue
        if name == known:
            continue
        dist = _distance(name.lower(), known.lower())
        if dist >= 1 and dist <= max_edit_distance:
            flags.append(
                _make_flag(
                    "typosquat",
                    SEVERITY_MEDIUM,
                    f"{name} resembles system binary '{known}'",
                    (
                        f"Heuristic: edit distance between '{name}' and the known "
                        f"system binary '{known}' is {dist} (<= {max_edit_distance}). "
                        f"Attackers often name implants one letter off a real binary "
                        f"to blend in -- but a genuinely mistyped or similarly-named "
                        f"tool would also match.  This is a heuristic, not ground truth."
                    ),
                )
            )
    return flags


# Rule 4: Short-lived process burst from the same parent

def check_burst(
    record: Dict[str, Any],
    recent_events: Sequence[Dict[str, Any]],
    window_seconds: float,
    threshold: int,
    now: Optional[float] = None,
) -> List[Dict[str, Any]]:
    """Flag when many processes were created from the same ppid within a
    short window.

    ``recent_events`` is any iterable of event dicts carrying at least
    ``ppid`` and ``created_at`` (the CLI uses ``EventHistory``).

    Heuristic: scripted malware unpacking launches a flurry of short-
    lived child processes in the space of a few seconds.  But so does a
    build system, a test harness, or a tight shell loop -- again,
    *look*, don't auto-condemn.
    """
    if not record or threshold <= 0 or window_seconds <= 0:
        return []
    ppid = record.get("ppid")
    if ppid is None:
        return []
    if now is None:
        import time

        now = time.time()

    cutoff = now - window_seconds
    count = 0
    for ev in recent_events:
        created = ev.get("created_at")
        if created is None or created < cutoff:
            continue
        if ev.get("ppid") == ppid:
            count += 1
    if count + 1 < threshold:
        return []
    name = _process_name(record) or str(record.get("pid"))
    return [
        _make_flag(
            "burst",
            SEVERITY_HIGH,
            f"{count + 1} processes from parent {ppid} in {window_seconds:g}s",
            (
                f"Heuristic: {count + 1} processes (including '{name}') were "
                f"created from parent pid {ppid} within the last "
                f"{window_seconds:g} seconds (threshold {threshold}).  Fast "
                f"process churn like this can indicate script/malware unpacking, "
                f"but build systems and test runners do the same thing.  This is "
                f"a heuristic signal, not a verdict."
            ),
        )
    ]


ALL_RULES = [
    "unusual_parent",
    "unusual_location",
    "typosquat",
    "burst",
]


class AnomalyEngine:
    """Runs every configured rule against one process event."""

    def __init__(self, config: Dict[str, Any]) -> None:
        self.config = config

    def evaluate(
        self,
        record: Dict[str, Any],
        tree: Any,
        history: Any,
        now: Optional[float] = None,
    ) -> List[Dict[str, Any]]:
        """Return flag dicts for ``record``, decorated with the process
        identity fields so the CLI/JSONL output is self-contained."""
        if now is None:
            import time

            now = time.time()

        ppid = record.get("ppid")
        parent = tree.get(ppid) if ppid else None

        flags: List[Dict[str, Any]] = []
        flags.extend(
            check_unusual_parent(
                record,
                parent,
                self.config.get("unusual_parent_child_pairs", []),
            )
        )
        flags.extend(
            check_unusual_location(
                record,
                self.config.get("world_writable_dirs", []),
            )
        )
        flags.extend(
            check_typosquat(
                record,
                self.config.get("known_binaries", []),
                int(self.config.get("typosquat_max_edit_distance", 1)),
            )
        )
        flags.extend(
            check_burst(
                record,
                history.recent(now - float(self.config.get("burst_window_seconds", 5.0))),
                float(self.config.get("burst_window_seconds", 5.0)),
                int(self.config.get("burst_threshold", 5)),
                now=now,
            )
        )

        name = _process_name(record)
        for f in flags:
            f.setdefault("pid", record.get("pid"))
            f.setdefault("ppid", record.get("ppid"))
            f.setdefault("process_name", name)
            f.setdefault("user", record.get("user"))
            f.setdefault("cmdline", record.get("cmdline") or [])
        return flags