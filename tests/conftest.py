"""Shared fixtures for proc-watch tests.

All records are synthetic dicts -- the tests never touch /proc, so they
produce identical results on any machine / CI runner.
"""

from __future__ import annotations

import pytest


def make_record(
    pid: int,
    ppid: int,
    name: str,
    exe: str | None = None,
    cmdline: list[str] | None = None,
    user: str = "alice",
    comm: str | None = None,
    start_time: float = 1000.0,
) -> dict:
    """Build a process record shaped like proc_reader.read_process output."""
    return {
        "pid": pid,
        "ppid": ppid,
        "comm": comm if comm is not None else name,
        "state": "S",
        "exe": exe if exe is not None else f"/usr/bin/{name}",
        "cmdline": cmdline if cmdline is not None else [f"/usr/bin/{name}"],
        "user": user,
        "start_time": start_time,
        "name": name,
    }


@pytest.fixture
def proc() -> dict:
    """A generic, boring, totally-normal process record."""
    return make_record(pid=1000, ppid=1, name="sleep", exe="/usr/bin/sleep")


@pytest.fixture
def parent_record() -> dict:
    return make_record(pid=500, ppid=1, name="nginx", exe="/usr/sbin/nginx")