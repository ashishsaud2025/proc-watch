# proc-watch

A small Linux tool for monitoring processes through `/proc`. It detects new processes, keeps track of parent-child relationships, and reports a few configurable anomaly patterns.

`proc-watch` is read-only. It does not kill, suspend, or signal processes, and it does not modify anything under `/proc`.

The rules are heuristics. A flag means that a process is worth checking, not that it is malicious.

## Features

* **Process monitoring:** polls `/proc` at a configurable interval, 1 second by default. For each new process, it records the PID, PPID, executable path, command line, user, and start time.
* **Process tree:** keeps parent-child relationships in memory, including cases where a child is detected before its parent.
* **Anomaly checks:** four configurable rules:

  1. **Unusual parent:** detects process relationships that are not normally expected, such as an `nginx` worker starting a shell.
  2. **Unusual executable location:** flags executables running from configured world-writable directories such as `/tmp` or `/dev/shm`.
  3. **Typosquatting:** compares process names against known system binaries using edit distance. For example, `systemdd` can be flagged as similar to `systemd`.
  4. **Process burst:** detects a large number of children created by the same parent within a short period.
* **Live output:** uses a `rich` table when available. Without `rich`, output falls back to plain text.
* **Event logging:** `--log events.jsonl` saves process events and triggered flags as JSONL.

## Requirements

* Linux
* Python 3.9+
* `/proc` filesystem

Optional dependencies:

* `rich` for the live process table
* `PyYAML` for the YAML configuration file

If `rich` is not installed, the program uses plain text output. If `PyYAML` is not installed, the built-in configuration defaults are used.

Windows support is not implemented. It is a possible future extension using WMI.

## Setup

```bash
# Create and activate a virtual environment
python -m venv .venv
source .venv/bin/activate

# Windows:
# .venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
```

Run the monitor:

```bash
python cli.py
```

You can also run it as a module:

```bash
python -m cli
```

For development and testing:

```bash
pip install -r requirements-dev.txt
pytest
```

The monitor can run without the optional dependencies. It will use plain text output and the built-in configuration defaults.

## Usage

```text
usage: proc-watch [-h] [-c CONFIG] [-i INTERVAL] [--log events.jsonl]
                  [--no-color] [--no-rich] [--once] [--max-events N]
                  [--quiet]

Observe process creation via /proc polling and flag anomaly heuristics.
Read-only: never kills, suspends, or signals any process.

options:
  -h, --help            show this help message and exit
  -c, --config CONFIG   YAML config file (default: config.yaml)
  -i, --interval INTERVAL
                        Poll interval in seconds (overrides config)
  --log events.jsonl    Append every event (+flags) to this file
  --no-color            Disable rich colour output
  --no-rich             Disable the rich live table
  --once                Snapshot /proc once, report, and exit
  --max-events N        Stop after N new-process events
  --quiet               Suppress non-flagged events
```

### Examples

Start the monitor with the default 1 second polling interval:

```bash
python cli.py
```

Poll every 250 ms and save events to a log:

```bash
python cli.py -i 0.25 --log events.jsonl
```

Take one snapshot and stop after 10 new-process events:

```bash
python cli.py --once --max-events 10
```

Only display flagged events and use plain text output:

```bash
python cli.py --quiet --no-rich
```

## Example output

On startup, the monitor prints information similar to:

```text
[proc-watch] polling /proc every 1.0s (config: config.yaml)
[proc-watch] logging events to events.jsonl
```

The live table contains:

```text
time pid ppid name cmdline user flags
```

Flags include their severity, for example:

```text
[HIGH] unusual_parent
```

When a rule triggers, additional information is printed:

```text
! unusual_parent: bash spawned by nginx
  Heuristic: 'bash' was spawned by a parent ('nginx') that is not
  expected to launch this kind of child on this system.
```

The exact output depends on the configured rules and the process being monitored.

### JSONL logging

With `--log events.jsonl`, each event is stored as a separate JSON object:

```json
{
  "created_at": 1739986000.12,
  "pid": 4123,
  "ppid": 4122,
  "record": {
    "pid": 4123,
    "ppid": 4122,
    "comm": "bash",
    "state": "S",
    "exe": "/tmp/x",
    "cmdline": ["/tmp/x", "-i"],
    "user": "alice",
    "start_time": 1739986000.0,
    "name": "bash"
  },
  "flags": [
    {
      "id": "unusual_location",
      "severity": "medium",
      "summary": "bash running from /tmp",
      "description": "Heuristic: ...",
      "pid": 4123,
      "ppid": 4122,
      "process_name": "bash",
      "user": "alice",
      "cmdline": ["/tmp/x", "-i"]
    }
  ]
}
```

## Configuration

The monitoring settings and anomaly rules are controlled through `config.yaml`.

| Key                           | Default  | Purpose                                                       |
| ----------------------------- | -------- | ------------------------------------------------------------- |
| `poll_interval`               | `1.0`    | `/proc` polling interval in seconds                           |
| `unusual_parent_child_pairs`  | see file | Parent and child patterns used by the unusual-parent rule     |
| `world_writable_dirs`         | see file | Directories checked by the executable-location rule           |
| `known_binaries`              | see file | Binary names used by the typosquat rule                       |
| `typosquat_max_edit_distance` | `1`      | Maximum edit distance for a typosquat match                   |
| `burst_window_seconds`        | `5.0`    | Time window used by the burst rule                            |
| `burst_threshold`             | `5`      | Number of children from one parent needed to trigger the rule |
| `history_maxlen`              | `5000`   | Maximum number of events kept in memory                       |

Parent and child patterns are matched against the process name rather than the full executable path.

Patterns support `|` for alternatives:

```yaml
child: "bash|sh|dash"
```

This matches `bash`, `sh`, or `dash`.

Standard `fnmatch` patterns are also supported:

```yaml
parent: "libreoffice*"
```

## Architecture

The project is split into a few modules.

```text
proc_reader.py
    Reads process information from /proc.
    Handles stat, cmdline, exe, status, user information,
    and process start-time conversion.

tree.py
    Maintains the ProcessTree, parent-child links,
    ancestor information, recent event history, and statistics.

rules.py
    Contains the individual anomaly checks:
    check_unusual_parent
    check_unusual_location
    check_typosquat
    check_burst

    AnomalyEngine runs the checks and attaches process
    information to the resulting flags.

cli.py
    Handles argument parsing, configuration loading,
    the monitoring loop, logging, and terminal output.
```

The rule functions work with process dictionaries and return flag dictionaries. They do not access `/proc` directly. This keeps the rules separate from the monitoring code and makes them easier to test.

## Limitations

The rules can produce false positives. They are intended as simple indicators rather than a complete malware detection system.

### 1. Unusual parent

A web server may legitimately start a shell as part of a CGI application or another web application feature. A browser development tool can also legitimately start a shell.

The rule only checks the observed parent-child relationship. If the parent exits before the next `/proc` poll, the relationship may not be detected.

### 2. Unusual executable location

Running programs from `/tmp`, `/var/tmp`, or `/dev/shm` is not necessarily suspicious. Development tools, build systems, package managers, cron jobs, and containers can all use these directories.

Only directories listed in `world_writable_dirs` are checked.

### 3. Typosquatting

A similarly named program is not necessarily malicious. A legitimate project or user program may differ from a system binary by one character.

The default edit distance is intentionally small. Setting the value to `0` disables the check:

```yaml
typosquat_max_edit_distance: 0
```

### 4. Process bursts

A large number of child processes can be normal. Commands such as:

```text
make -j
pip
npm install
cargo build
```

can create many processes in a short period.

The current rule counts all children created by the same parent during the configured window. It does not distinguish between short-lived and long-lived children.

### 5. `/proc` polling

`proc-watch` samples `/proc` instead of receiving process creation events directly. A process that starts and exits between two polls may never be detected.

Some `/proc/<pid>` files may also be inaccessible for processes owned by other users. In these cases, the process record may be incomplete.

Kernel threads do not have a normal executable path, so their name falls back to `comm`.

PID reuse can make long-running process trees ambiguous. The monitor records the process start time to reduce this problem, but it does not completely eliminate it.

The process start time is calculated using the kernel boot time (`btime`) and the process start-time value from `/proc`. The cached boot time is refreshed once per minute.

### 6. Platform support

`proc-watch` currently supports Linux. Windows WMI support may be added later.

On systems without `/proc`, the program exits with an error instead of continuing with incomplete information.