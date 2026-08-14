"""Command-line entry point and monitoring loop for proc-watch.

Defensively *observes* processes via /proc polling and prints/reports
anomaly heuristics.  It never kills, suspends, or signals any process.
"""

from __future__ import annotations

import argparse
import datetime as _dt
import json
import os
import signal
import sys
import time
from typing import TYPE_CHECKING, Any, Dict, List, Optional

import proc_reader
import rules
import tree as tree_module

try:
    import yaml  # PyYAML
except ImportError:  # pragma: no cover - handled in main()
    yaml = None

if TYPE_CHECKING:
    from rich.console import Console
    from rich.live import Live
    from rich.table import Table
else:
    # At runtime, rich is optional: bind the real classes, or None if
    # missing.  The TYPE_CHECKING import above keeps annotations like
    # `Optional[Live]` and `-> Table` valid for type checkers even when
    # rich is not installed.
    try:
        from rich.console import Console
        from rich.live import Live
        from rich.table import Table
    except ImportError:  # pragma: no cover - handled by RichReporter fallback
        Console = None  # type: ignore[assignment,misc]
        Live = None  # type: ignore[assignment,misc]
        Table = None  # type: ignore[assignment,misc]

DEFAULT_CONFIG = "config.yaml"

# Colours for rich, or plain labels when rich is missing.
_SEVERITY_STYLE = {
    rules.SEVERITY_HIGH: ("red", "[HIGH]"),
    rules.SEVERITY_MEDIUM: ("yellow", "[MED ]"),
    rules.SEVERITY_LOW: ("cyan", "[LOW ]"),
}


def parse_args(argv: Optional[List[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="proc-watch",
        description=(
            "Observe process creation via /proc polling and flag anomaly "
            "heuristics (unusual parent->child, world-writable path, "
            "typosquatting names, short-lived bursts). Read-only: it never "
            "kills, suspends, or signals any process."
        ),
    )
    parser.add_argument(
        "-c",
        "--config",
        default=DEFAULT_CONFIG,
        help=f"YAML config file (default: {DEFAULT_CONFIG})",
    )
    parser.add_argument(
        "-i",
        "--interval",
        type=float,
        default=None,
        help="Poll interval in seconds (overrides config)",
    )
    parser.add_argument(
        "--log",
        metavar="events.jsonl",
        default=None,
        help="Append every event (+flags) as a JSON line to this file",
    )
    parser.add_argument(
        "--no-color",
        action="store_true",
        help="Disable rich colour output (plain text fallback)",
    )
    parser.add_argument(
        "--no-rich",
        action="store_true",
        help="Disable the rich live table entirely (plain lines only)",
    )
    parser.add_argument(
        "--once",
        action="store_true",
        help="Snapshot /proc once, report, and exit (useful for testing)",
    )
    parser.add_argument(
        "--max-events",
        type=int,
        default=None,
        metavar="N",
        help="Stop after N new-process events (useful for testing)",
    )
    parser.add_argument(
        "--quiet",
        action="store_true",
        help="Suppress non-flagged events in the live output; flags still shown",
    )
    return parser.parse_args(argv)


def load_config(path: str) -> Dict[str, Any]:
    """Load YAML config; falls back to sane defaults if the file is
    missing, keeping the tool usable with zero setup."""
    if not os.path.exists(path):
        print(
            f"[proc-watch] config '{path}' not found; using built-in defaults",
            file=sys.stderr,
        )
        return {}
    if yaml is None:
        raise SystemExit(
            "PyYAML is required to read the config file. "
            "Install with: pip install pyyaml"
        )
    try:
        with open(path, "r", encoding="utf-8") as fh:
            data = yaml.safe_load(fh) or {}
    except yaml.YAMLError as exc:
        raise SystemExit(f"[proc-watch] failed to parse config '{path}': {exc}")
    if not isinstance(data, dict):
        raise SystemExit(f"[proc-watch] config '{path}' must map to a YAML mapping")
    return data


def _compute_settings(config: Dict[str, Any], args: argparse.Namespace) -> Dict[str, Any]:
    def get(name: str, default: Any) -> Any:
        if name == "poll_interval" and args.interval is not None:
            return args.interval
        return config.get(name, default)

    return {
        "poll_interval": float(get("poll_interval", 1.0)),
        "unusual_parent_child_pairs": list(get("unusual_parent_child_pairs", [])),
        "world_writable_dirs": list(get("world_writable_dirs", ["/tmp", "/var/tmp", "/dev/shm"])),
        "known_binaries": list(get("known_binaries", ["systemd", "sshd", "bash", "sh"])),
        "typosquat_max_edit_distance": int(get("typosquat_max_edit_distance", 1)),
        "burst_window_seconds": float(get("burst_window_seconds", 5.0)),
        "burst_threshold": int(get("burst_threshold", 5)),
        "history_maxlen": int(get("history_maxlen", 5000)),
    }


def _now_str(ts: Optional[float]) -> str:
    if ts is None:
        return "?"
    return _dt.datetime.fromtimestamp(ts).strftime("%H:%M:%S")


def _format_cmdline(cmdline: List[str]) -> str:
    if not cmdline:
        return "?"
    parts: List[str] = []
    for part in cmdline:
        if part and any(c.isspace() for c in part):
            parts.append(f"'{part}'")
        else:
            parts.append(part)
    return " ".join(parts)


def _make_row(event: Dict[str, Any]) -> List[str]:
    rec = event.get("record", {})
    flags = event.get("flags", [])
    labels = " ".join(
        f"{_SEVERITY_STYLE.get(f.get('severity'), ('', f.get('id')))[1]}"
        f"{f.get('id')}"
        for f in flags
    )
    return [
        _now_str(event.get("created_at")),
        str(rec.get("pid", "?")),
        str(rec.get("ppid", "?")),
        rec.get("name") or rec.get("comm") or "?",
        _format_cmdline(rec.get("cmdline") or []),
        str(rec.get("user") or "?"),
        labels or "",
    ]


def _annotation_for(flag: Dict[str, Any]) -> str:
    return f"{flag.get('id')}: {flag.get('summary')} -- {flag.get('description')}"


class JsonlLogger:
    """Streams each event + flags as one JSON line (append mode)."""

    def __init__(self, path: str) -> None:
        self.path = path
        self._fh = open(path, "a", encoding="utf-8")

    def write(self, event: Dict[str, Any]) -> None:
        line = json.dumps(event, ensure_ascii=False, separators=(",", ":"))
        self._fh.write(line + "\n")
        self._fh.flush()

    def close(self) -> None:
        try:
            self._fh.close()
        except OSError:
            pass


class RichReporter:
    """Live-updating rich table (fallback: plain text lines)."""

    def __init__(self, use_rich: bool, color: bool, quiet: bool) -> None:
        self.use_rich = use_rich and Table is not None and Live is not None
        self.color = color and self.use_rich
        self.quiet = quiet
        self.console = Console() if self.use_rich else None
        self.live: Optional[Live] = None
        self.rows: List[Dict[str, Any]] = []
        self.start = time.time()

    def start_live(self) -> None:
        if self.use_rich:
            self.live = Live(self._build_table(), console=self.console, refresh_per_second=4)

    def _build_table(self) -> Table:
        assert self.console is not None
        table = Table(title="proc-watch -- process creation events")
        for col in ("time", "pid", "ppid", "name", "cmdline", "user", "flags"):
            table.add_column(col, overflow="fold", no_wrap=(col in ("time", "pid", "ppid", "user", "flags")))
        for row in self.rows[-200:]:
            table.add_row(*row)
        table.caption = (
            f"seen pids: {len(self.rows)} tracked | uptime {time.time() - self.start:.0f}s | "
            f"heuristics only -- NOT ground truth"
        )
        return table

    def render_static(self) -> None:
        """Plain-text fallback tableau of recent rows (no live refresh)."""
        if self.console is None:
            for row in self.rows[-200:]:
                print("\t".join(row))
            return
        self.console.print(self._build_table())

    def update(self, event: Dict[str, Any], now: float) -> None:
        rec = event.get("record", {})
        flags = event.get("flags", [])
        short = _make_row(event)
        flagged = len(flags) > 0
        if self.quiet and not flagged:
            return
        self.rows.append(short)
        if self.live is not None:
            self.live.update(self._build_table())
            if flagged:
                for f in flags:
                    self.live.console.print(f"  ! {_annotation_for(f)}")
        else:
            if not self.quiet and flags and not self.color:
                print("  ! " + " | ".join(_annotation_for(f) for f in flags))
            elif flags and self.color:
                pass  # coloured annotation rendering omitted in fallback
            elif not flags and not self.quiet:
                pass

    def finish(self) -> None:
        if self.live is not None:
            self.live.stop()
        self.render_static()


class Monitor:
    """Handles one full poll cycle: detect new PIDs, read them, evaluate
    rules, record to history, log, and report."""

    def __init__(
        self,
        settings: Dict[str, Any],
        reporter: RichReporter,
        logger: Optional[JsonlLogger] = None,
    ) -> None:
        self.settings = settings
        self.tree = tree_module.ProcessTree()
        self.history = tree_module.EventHistory(maxlen=settings["history_maxlen"])
        self.engine = rules.AnomalyEngine(settings)
        self.reporter = reporter
        self.logger = logger
        self.stats = tree_module.TreeStats()
        self.last_pids: set = set()
        self.event_count = 0

    def poll_once(self, now: float) -> int:
        """Scan /proc, process newly-seen PIDs, return number of new events."""
        current = set(proc_reader.list_pids())
        new_pids = current - self.last_pids
        # Always refresh the whole snapshot so parent nodes exist for the
        # unusual-parent rule before the child is evaluated.
        records = {pid: proc_reader.read_process(pid) for pid in current}
        for pid in new_pids:
            record = records.get(pid)
            if record is None or record.get("pid") is None:
                continue
            parent = records.get(record.get("ppid")) if record.get("ppid") else None
            if parent:
                self.tree.add(parent)
            self.tree.add(record)
            self.stats.observe(record, now)

            flags = self.engine.evaluate(record, self.tree, self.history, now=now)
            event = {
                "created_at": now,
                "pid": pid,
                "ppid": record.get("ppid"),
                "record": record,
                "flags": flags,
            }
            self.history.add(event)
            if self.logger:
                self.logger.write(event)
            self.reporter.update(event, now)
            self.event_count += 1
        self.last_pids = current
        return len(new_pids)


def _install_sigint() -> None:
    def _handle(signum, frame):  # noqa: ARG001
        raise KeyboardInterrupt

    try:
        signal.signal(signal.SIGINT, _handle)
    except (ValueError, OSError):
        pass


def main(argv: Optional[List[str]] = None) -> int:
    args = parse_args(argv)
    config = load_config(args.config)
    settings = _compute_settings(config, args)

    try:
        import proc_reader as _pr  # noqa: F401

        _probe = _pr.list_pids()
        if not _probe:
            raise SystemExit(
                "No PIDs found under /proc -- is this Linux? proc-watch targets "
                "Linux (Windows WMI is a documented stretch goal)."
            )
    except FileNotFoundError:
        raise SystemExit(
            "/proc is not available. proc-watch targets Linux; "
            "Windows WMI support is a stretch goal."
        ) from None

    logger = JsonlLogger(args.log) if args.log else None
    reporter = RichReporter(use_rich=not args.no_rich, color=not args.no_color, quiet=args.quiet)
    monitor = Monitor(settings=settings, reporter=reporter, logger=logger)

    print(
        f"[proc-watch] polling /proc every {settings['poll_interval']}s "
        f"(config: {args.config}) -- heuristics only, not ground truth"
    )
    if args.log:
        print(f"[proc-watch] logging events to {args.log}")

    reporter.start_live()
    _install_sigint()
    try:
        now = time.time()
        monitor.poll_once(now)  # baseline: only fills tree, no events reported
        monitor.event_count = 0  # baseline snapshot is not an "event"
        monitor.history.clear()
        while True:
            time.sleep(settings["poll_interval"])
            now = time.time()
            monitor.poll_once(now)
            if args.max_events and monitor.event_count >= args.max_events:
                break
            if args.once:
                break
    except KeyboardInterrupt:
        pass
    finally:
        reporter.finish()
        if logger:
            logger.close()

    print(f"[proc-watch] done -- processed {monitor.event_count} new-process events")
    return 0


if __name__ == "__main__":
    sys.exit(main())