"""All /proc parsing for proc-watch.

Linux-only.  Every read here is *defensive*: a process can exit between
listing and reading, permissions can be denied for other users'
processes, and kernel threads do not have an executable.  Each helper
returns partial data rather than raising, so a single unreadable process
never takes down the monitoring loop.

Nothing in this module ever writes to a process or to /proc; it only
observes.
"""

from __future__ import annotations

import os
import time
from typing import Any, Dict, List, Optional

try:
    import pwd  # Unix-only
except ImportError:  # pragma: no cover - only exercised on non-Unix systems
    pwd = None

try:
    _CLK_TCK: float = float(os.sysconf("SC_CLK_TCK"))
except (AttributeError, OSError, ValueError):  # pragma: no cover
    _CLK_TCK = 100.0

_BTIME: Optional[float] = None
_BTIME_AT: float = 0.0


def _read_boot_time() -> Optional[float]:
    """Seconds since epoch at kernel boot, from /proc/stat."""
    try:
        with open("/proc/stat", "r", encoding="utf-8", errors="replace") as fh:
            for line in fh:
                if line.startswith("btime "):
                    return float(line.split()[1])
    except (OSError, ValueError, IndexError):
        pass
    return None


def boot_time() -> Optional[float]:
    """Cached /proc/stat boot time (refreshed at most once per minute)."""
    global _BTIME, _BTIME_AT
    now = time.monotonic()
    if _BTIME is None or (now - _BTIME_AT) > 60.0:
        _BTIME = _read_boot_time()
        _BTIME_AT = now
    return _BTIME


def list_pids() -> List[int]:
    """Return every numeric entry in /proc (i.e. current PIDs)."""
    pids: List[int] = []
    try:
        entries = os.listdir("/proc")
    except OSError:
        return pids
    for entry in entries:
        if entry.isdigit():
            try:
                pids.append(int(entry))
            except ValueError:
                pass
    return pids


def _parse_stat(pid: int) -> Dict[str, Any]:
    """Parse /proc/<pid>/stat -> comm, state, ppid, starttime (in ticks).

    Field positions follow linux/fs/proc/array.c; the executable name
    (field 2) can contain spaces/parentheses, so we split around the
    first '(' and the last ')'.
    """
    try:
        with open(f"/proc/{pid}/stat", "r", encoding="utf-8", errors="replace") as fh:
            data = fh.read()
    except OSError:
        return {}

    try:
        lparen = data.find("(")
        rparen = data.rfind(")")
        if lparen == -1 or rparen == -1 or rparen <= lparen:
            return {}
        comm = data[lparen + 1 : rparen]
        rest = data[rparen + 2 :].split()

        result: Dict[str, Any] = {"comm": comm}
        if len(rest) >= 2:
            result["state"] = rest[0]
            if rest[1].lstrip("+-").isdigit():
                result["ppid"] = int(rest[1])
        if len(rest) >= 20 and rest[19].lstrip("+-").isdigit():
            result["starttime"] = int(rest[19])
        return result
    except (ValueError, IndexError):  # pragma: no cover - malformed stat line
        return {}


def read_exe(pid: int) -> Optional[str]:
    """Resolve /proc/<pid>/exe symlink; None if unavailable (kernel thread,
    permission denied, or process already gone)."""
    try:
        return os.readlink(f"/proc/{pid}/exe")
    except OSError:
        return None


def read_cmdline(pid: int) -> List[str]:
    """Read /proc/<pid>/cmdline as a list of args (NUL-separated)."""
    try:
        with open(f"/proc/{pid}/cmdline", "rb") as fh:
            raw = fh.read()
    except OSError:
        return []
    parts = [p.decode("utf-8", errors="replace") for p in raw.split(b"\x00")]
    return [p for p in parts if p]


def read_user(pid: int) -> Optional[str]:
    """Real username of the process owner; falls back to the raw UID."""
    uid: Optional[int] = None
    try:
        with open(f"/proc/{pid}/status", "r", encoding="utf-8", errors="replace") as fh:
            for line in fh:
                if line.startswith("Uid:"):
                    parts = line.split()
                    if len(parts) >= 2 and parts[1].isdigit():
                        uid = int(parts[1])
                    break
    except OSError:
        pass
    if uid is None:
        return None
    if pwd is not None:
        try:
            return pwd.getpwuid(uid).pw_name
        except (KeyError, OSError):
            pass
    return str(uid)


def _compute_start_time(starttime_ticks: Optional[int]) -> Optional[float]:
    """Epoch-seconds at process start = boot time + starttime/CLK_TCK."""
    if starttime_ticks is None:
        return None
    btime = boot_time()
    if btime is None:
        return None
    return btime + starttime_ticks / _CLK_TCK


def read_process(pid: int) -> Dict[str, Any]:
    """Capture one process record.

    Every field is best-effort; a fast-exiting process may yield mostly
    None values.  ``name`` is the basename of the resolved executable,
    falling back to the kernel comm name.
    """
    stat = _parse_stat(pid)
    exe = read_exe(pid)
    cmdline = read_cmdline(pid)
    user = read_user(pid)
    comm = stat.get("comm")
    name = os.path.basename(exe) if exe else (comm or None)
    return {
        "pid": pid,
        "ppid": stat.get("ppid"),
        "comm": comm,
        "state": stat.get("state"),
        "exe": exe,
        "cmdline": cmdline,
        "user": user,
        "start_time": _compute_start_time(stat.get("starttime")),
        "name": name,
    }