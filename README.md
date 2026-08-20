# blocking-io-check-py

[![Lint and Format](https://github.com/ryuichi1208/blocking-io-check-py/actions/workflows/lint.yml/badge.svg)](https://github.com/ryuichi1208/blocking-io-check-py/actions/workflows/lint.yml)
[![Python 3.12+](https://img.shields.io/badge/python-3.12+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

Find the synchronous call that is stalling your asyncio event loop — in a running
production process, without changing a line of its code.

`blocking-io-check` uses eBPF to time every I/O syscall a Python process makes and
tells you which ones actually blocked. It does not just report flags; it reaches a
verdict, and it is deliberately conservative about calling something a stall.

## Why

One synchronous `requests.get()` inside an async handler stalls the entire event
loop. Every other request served by that worker waits behind it. The symptom is
distinctive and maddening:

- p99 latency spikes to seconds
- CPU sits at 4%
- no errors, no traceback, nothing in the logs
- your profiler shows the process was idle
- your APM shows a slow span with no slow child

Nothing is on fire. The process is *waiting*, and no Python-level tool can see
what it is waiting on.

**Why not just read the code?** Because the blocking call is usually three
libraries deep. It is a lazily-imported SDK that builds its own HTTP session, or
a DNS resolution inside `getaddrinfo`, or a database driver that is async
everywhere except its connection setup. Grepping for `requests` does not find it.

**Why eBPF?** Because it observes the real syscalls of an unmodified, already
running process. No code change, no restart, no import hook, no monkeypatching,
no redeploy to add instrumentation. You attach to the PID that is misbehaving
right now.

**What this is not.** Not a profiler, not an APM, not a sampling tool. It answers
exactly one question — *which I/O operations blocked, for how long, and was that
a bug?* — and tries to answer it precisely.

## How it works

For any I/O syscall, four facts determine whether it stalled the event loop:

| Fact | Where it comes from |
|---|---|
| Is `O_NONBLOCK` set on the fd? | `/proc/<pid>/fdinfo` at startup, then `fcntl`/`ioctl`/`socket`/`accept4` |
| Is the fd registered with epoll? | `epoll_ctl(ADD/DEL)` via a libc uprobe |
| Was `MSG_DONTWAIT` passed? | the syscall's own flags argument |
| How long did it actually take? | `sys_enter_*` → `sys_exit_*` timestamp pair |

The fourth is the one that matters most, and the reason for this tool: a socket
being "blocking" is harmless if the data was already there. It is a bug only when
it *waited*.

```
  target process (unmodified)          kernel                        userspace
 ┌───────────────────────────┐  ┌───────────────────────┐  ┌────────────────────┐
 │ fcntl(F_SETFL, O_NONBLOCK)│─▶│ uprobe  ──▶ fd_nonblock│  │                    │
 │ fcntl(F_GETFL)            │─▶│ uretprobe ─▶  (tri-state)│                    │
 │ ioctl(FIONBIO)            │─▶│ uprobe        │        │  │                    │
 │ epoll_ctl(ADD/DEL)        │─▶│ uprobe  ──▶ fd_epoll   │  │                    │
 │ socket(SOCK_NONBLOCK)     │─▶│ tracepoint    │        │  │                    │
 │                           │  │               ▼        │  │                    │
 │ connect() / accept4()     │─▶│ tracepoint ─▶ peer_map │  │                    │
 │                           │  │               │        │  │                    │
 │ recvfrom() ──enter────────│─▶│ io_start{ts}  │        │  │                    │
 │            └──exit────────│─▶│ duration_ns ──┴─▶      │  │                    │
 │                           │  │   classify() ─▶ verdict│  │                    │
 │ close()                   │─▶│ tracepoint ─▶ cleanup  │  │                    │
 └───────────────────────────┘  └───────┬───────────────┘  │                    │
                                        │ perf ring buffer │                    │
                                        └─────────────────▶│ decode ─▶ filter   │
                                                           │   ├─▶ format ─▶ out│
                                                           │   └─▶ aggregate    │
                                                           └────────────────────┘
```

### The state tables

| Map | Holds | Populated by |
|---|---|---|
| `fd_nonblock` | per-`(pid,fd)` blocking state, **tri-state** | `/proc` seeding at startup, `fcntl`, `ioctl`, `socket`, `accept4` |
| `fd_epoll` | which fds are registered with epoll | `epoll_ctl(ADD)`, removed on `EPOLL_CTL_DEL` |
| `peer_map` | remote address per `(pid,fd)` | `connect`, `accept4`; cleared on `close` |
| `io_start` | in-flight syscall start time, keyed by thread | every `sys_enter_*` |
| `loop_tid` | which threads run an event loop, keyed by `(pid,tid)` | any thread that calls `epoll_wait` |

### Two design decisions worth knowing

**`nonblock` is tri-state, not a boolean.** A missing map entry means *unknown*,
not *blocking*. Earlier versions of this tool learned the flag only by watching
`fcntl` calls happen, so any socket configured before the tracer attached — which
is every socket in a running asyncio app — was reported as blocking. That made
every result untrustworthy. Now the state is seeded from `/proc/<pid>/fdinfo` at
startup, and when it genuinely cannot be determined the tool says `?` and
refuses to call it a stall. **Being conservative beats being confidently wrong.**

**Blocking I/O on an executor thread is not a stall.** `loop.run_in_executor()`
exists precisely so blocking calls can happen off the event loop. A blocking
`read` on a `ThreadPoolExecutor` worker is that thread doing its job. The tool
marks a thread as an event-loop thread when it observes `epoll_wait` on it, and
only reports `STALL` there. Use `--all-threads` to disable this.

## Requirements

- Linux kernel 4.9+ (5.x recommended)
- Python 3.12+
- BCC (BPF Compiler Collection) — see below
- root (or `CAP_BPF` + `CAP_PERFMON`)

## Installation

### 1. Install BCC

> [!IMPORTANT]
> **Do not `pip install bcc`.** The package named `bcc` on PyPI is an unrelated
> project. The real BCC is distro-packaged and cannot be installed from PyPI.

```bash
# Ubuntu / Debian
sudo apt install -y bpfcc-tools python3-bpfcc linux-headers-$(uname -r)

# Fedora / RHEL
sudo dnf install -y bcc bcc-tools python3-bcc kernel-devel

# Arch
sudo pacman -S bcc bcc-tools python-bcc
```

Verify it works:

```bash
sudo python3 -c "from bcc import BPF; print('ok')"
```

### 2. Install this tool

```bash
git clone https://github.com/ryuichi1208/blocking-io-check-py
cd blocking-io-check-py
uv sync
```

### 3. The BCC + virtualenv gotcha

This is the thing people get stuck on. BCC installs into the **system** Python's
`site-packages`, so a normal virtualenv cannot see it. Either point Python at the
system packages:

```bash
sudo PYTHONPATH=/usr/lib/python3/dist-packages uv run blocking-io-check --pid 1234
```

or create the venv with system site-packages visible:

```bash
uv venv --system-site-packages
sudo .venv/bin/blocking-io-check --pid 1234
```

Verify:

```bash
sudo blocking-io-check --version
```

## Quick start

Trace a process for 30 seconds and show what blocked:

```bash
sudo blocking-io-check --pid $(pgrep -f uvicorn) -d 30 --summary
```

```
Tracing blocking I/O for PID 40213 for 30.0s (showing >=1.0ms, stall >=50.0ms)… Ctrl-C to stop
14:02:33.481 pid= 40213 comm=uvicorn          fd=14   op=recvfrom   dur=  1203.400ms ret=8192   flags=B--- peer=10.0.7.22:5432   verdict=STALL
14:02:34.702 pid= 40213 comm=uvicorn          fd=14   op=recvfrom   dur=   980.100ms ret=8192   flags=B--- peer=10.0.7.22:5432   verdict=STALL

=== summary (18422 events, 214 blocking, 214 stalls, 30.0s) ===
comm     pid    op        peer              count  block  stall     total       max       p50       p95       p99
uvicorn  40213  recvfrom  10.0.7.22:5432      214    214    214  24102.30  1203.400   112.400   980.100  1203.400
uvicorn  40213  recvfrom  10.0.3.14:5432     8801      0      0    120.30     0.900     0.010     0.040     0.090
```

The first summary row names the culprit: 214 blocking reads against
`10.0.7.22:5432`, 24 seconds of event-loop time lost.

## Usage

### Options

| Flag | Arg | Default | Description |
|---|---|---|---|
| `-p`, `--process-name` | NAME | `python3` | Target process name (`comm`, max 15 bytes) |
| `--pid` | PID | — | Target a specific PID (overrides `--process-name`) |
| `-b`, `--bpf-file` | PATH | bundled | Path to the eBPF C source |
| `--min-latency` | MS | `1.0` | Only *display* I/O at least this slow; `0` reports everything |
| `--stall-latency` | MS | `50.0` | Blocking I/O at least this slow is judged a `STALL` |
| `--file-io` | | off | Also trace `openat`/`fsync`/`fdatasync` (noisy) |
| `--no-include-wait` | | — | Do not trace `epoll_wait`/`poll`/`select` |
| `--all-threads` | | off | Report stalls on any thread, not just event-loop threads |
| `--op` | LIST | all | Comma-separated ops to show, e.g. `recvfrom,read` |
| `--hide-dns` | | off | Hide port 53 traffic (IPv4 **and** IPv6) |
| `--hide-netlink` | | off | Hide `AF_NETLINK` traffic |
| `--only-blocking` | | off | Only show `WARN` and `STALL` events |
| `--json` | | off | Emit JSON Lines |
| `-o`, `--output` | FILE | stdout | Write events to a file (line-buffered) |
| `--no-color` | | — | Disable color (also respects `NO_COLOR`) |
| `--summary` | | off | Print a summary on exit |
| `--summary-only` | | off | Print only the summary |
| `--group-by` | KEY | `peer` | Summary grouping: `peer`, `op`, `pid`, `fd` |
| `--top` | N | `20` | Summary rows to show |
| `-d`, `--duration` | SECONDS | — | Stop after N seconds |
| `--fail-on-blocking` | | off | Exit `3` if blocking I/O was detected |
| `--version` | | — | Print version |

### Exit codes

| Code | Meaning |
|---|---|
| `0` | Ran successfully (this is the default even when stalls are found) |
| `1` | Setup failure: not Linux, kernel too old, BCC missing, no permission |
| `2` | Usage error (argparse) |
| `3` | Blocking I/O detected — **only** with `--fail-on-blocking` |

`3` is distinct from `1` so CI can tell "the tool broke" from "the tool found
something".

### Recipes

```bash
# Capture 60 seconds to a file for later analysis
sudo blocking-io-check --pid 1234 -d 60 --json -o /tmp/io.jsonl

# Only the genuinely slow stuff, summary only
sudo blocking-io-check --pid 1234 -d 30 --min-latency 10 --summary-only

# Quiet the usual noise
sudo blocking-io-check --pid 1234 --hide-dns --hide-netlink

# See absolutely everything (the old default behaviour)
sudo blocking-io-check --pid 1234 --min-latency 0

# Be stricter about what counts as a stall
sudo blocking-io-check --pid 1234 --stall-latency 10

# Which peers cost the most event-loop time?
jq -s 'group_by(.peer) | map({peer: .[0].peer, ms: (map(.duration_ms) | add)})
       | sort_by(-.ms) | .[:5]' /tmp/io.jsonl

# Count by verdict
jq -r .verdict /tmp/io.jsonl | sort | uniq -c

# Use as a CI gate
sudo blocking-io-check --pid $APP_PID -d 20 --fail-on-blocking --summary-only
```

## Output formats

### Text

```
14:02:33.481 pid= 40213 comm=uvicorn          fd=14   op=recvfrom   dur=  1203.400ms ret=8192   flags=B--- peer=10.0.7.22:5432   verdict=STALL
└──────┬───┘ └───┬────┘ └──────┬───────┘ └─┬─┘ └────┬────┘ └───────┬──────┘ └───┬──┘ └───┬───┘ └────────┬────────┘ └──────┬─────┘
   wall clock   pid      process name     fd      syscall      how long it     return  flag     remote peer         verdict
                                                               actually took   value   summary
```

Every field is `key=value`, so the output stays grep-friendly. `verdict` is last,
so both `| grep verdict=STALL` and `| awk '{print $NF}'` work.

The `flags` field is a fixed-width 4-character summary:

| Position | Character | Meaning |
|---|---|---|
| 1 | `N` / `B` / `?` | fd is **N**on-blocking / **B**locking / state unknown |
| 2 | `E` / `-` | registered with **E**poll |
| 3 | `D` / `-` | `MSG_**D**ONTWAIT` was passed |
| 4 | `T` / `-` | process name was **T**runcated to 15 bytes |

So `flags=NE--` is a healthy asyncio socket and `flags=B---` is a blocking socket
nobody is polling — the shape of a stall.

### JSON Lines

One object per line, stdout only. With `--json`, all diagnostics go to stderr so
stdout stays a homogeneous stream.

```json
{
  "ts_ns": 140233481000000,
  "time": "2026-08-21T14:02:33.481123Z",
  "pid": 40213,
  "tid": 40213,
  "comm": "uvicorn",
  "fd": 14,
  "op": "recvfrom",
  "op_code": 1,
  "duration_ns": 1203400000,
  "duration_ms": 1203.4,
  "ret": 8192,
  "nonblock": 0,
  "via_epoll": false,
  "msg_dontwait": false,
  "family": 2,
  "family_name": "AF_INET",
  "peer": "10.0.7.22:5432",
  "peer_addr": "10.0.7.22",
  "peer_port": 5432,
  "verdict": "STALL"
}
```

| Key | Type | Null? | Meaning |
|---|---|---|---|
| `ts_ns` | int | | Raw kernel monotonic timestamp at syscall entry |
| `time` | string | | Wall-clock ISO 8601 UTC |
| `pid` / `tid` | int | | Process id / thread id |
| `comm` | string | | Process name, truncated to 15 bytes by the kernel |
| `fd` | int | | File descriptor; `-1` for ops without one |
| `op` | string | | Syscall label; `opN` if the C side is newer than the decoder |
| `op_code` | int | | Raw op code, always present even for unknown ops |
| `duration_ns` / `duration_ms` | int / float | | How long the syscall took |
| `ret` | int | | Syscall return value; negative is `-errno` (e.g. `-11` = `EAGAIN`) |
| `nonblock` | int | | **Tri-state**: `1` non-blocking, `0` blocking, `-1` unknown |
| `via_epoll` / `msg_dontwait` | bool | | |
| `family` / `family_name` | int / string | | Address family |
| `peer` | string | | Human-readable peer, always present |
| `peer_addr` / `peer_port` | string / int | yes | `null` for netlink and non-socket ops |
| `verdict` | string | | `OK`, `IDLE`, `WARN`, or `STALL` |

`nonblock` is an int rather than a bool because it must be able to say "unknown".

Key stability: within a minor version, keys are only ever added, never renamed or
removed.

### Summary

Rows are sorted by **total blocked time descending**, because the question a
summary should answer is "what do I fix first".

Percentiles use **nearest-rank** (not linear interpolation), so every reported
value is a latency that actually occurred and can be looked up in a log. Above
2048 samples per group, values are drawn from a fixed-size reservoir
(Algorithm R), which keeps memory bounded on long runs; below that the
percentiles are exact. Counts and totals are always exact regardless.

## Interpreting the verdict

There are two independent thresholds, and the distinction matters:

- `--min-latency` (default 1ms) controls **what you see**. It is applied in the
  kernel, so filtered events never cross the perf buffer — this is what keeps the
  tool cheap on a busy process.
- `--stall-latency` (default 50ms) controls **what counts as a stall**. A blocking
  read of 5ms is worth looking at but is not an event-loop stall; a blocking read
  of 800ms is.

They are separate on purpose. If they were the same knob, `--min-latency 0` would
mean "show everything" *and* "call every blocking read a stall", which would make
the verdict meaningless.

| Verdict | Meaning | What to do |
|---|---|---|
| `OK` | Fast, or non-blocking, or explicitly non-waiting | Nothing |
| `IDLE` | A waiting syscall (`epoll_wait`/`poll`/`select`) | Nothing — this is the event loop working correctly |
| `WARN` | Something inconsistent: a non-blocking fd that waited a very long time, or a blocking fd that *is* in epoll | Investigate, but this may be a tracking artifact rather than a bug |
| `STALL` | A blocking fd, not in epoll, that waited past the threshold, on a thread that runs an event loop | **This is a real event-loop stall.** Fix it. |

> [!NOTE]
> **A long `epoll_wait` is not a problem.** It means the event loop had nothing to
> do and was correctly idling. This is the single most common misreading of
> syscall traces, which is why such ops get their own `IDLE` verdict and are never
> reported as stalls.

### Healthy vs. stalled

A healthy asyncio process — non-blocking sockets, registered with epoll,
returning `EAGAIN` in microseconds, with the loop idling in `epoll_wait`:

```
op=recvfrom   dur=     0.021ms ret=-11    flags=NE-- peer=10.0.3.14:5432  verdict=OK
op=sendto     dur=     0.043ms ret=137    flags=NE-- peer=10.0.3.14:5432  verdict=OK
op=epoll_wait dur=    48.000ms ret=1      flags=?--- peer=-               verdict=IDLE
```

A stalled event loop — a blocking socket nobody is polling, waiting over a
second, on the loop thread:

```
op=recvfrom   dur=  1203.400ms ret=8192   flags=B--- peer=10.0.7.22:5432  verdict=STALL
op=connect    dur=  3004.120ms ret=0      flags=B--- peer=10.0.7.22:5432  verdict=STALL
```

The `flags` column tells the whole story: `NE--` versus `B---`.

## Worked example: a blocking `requests` call in an async service

**Symptom.** p99 latency 2s, CPU 4%, no errors.

**Reproducer.** One handler is correctly async; the other is not:

```python
# app.py
import httpx
import requests
from fastapi import FastAPI

app = FastAPI()
client = httpx.AsyncClient()
UPSTREAM = "http://10.0.7.22:8080/slow"

@app.get("/good")
async def good():
    r = await client.get(UPSTREAM)          # non-blocking, driven by the event loop
    return {"len": len(r.text)}

@app.get("/bad")
async def bad():
    r = requests.get(UPSTREAM)              # synchronous — stalls the whole loop
    return {"len": len(r.text)}
```

```bash
uvicorn app:app --port 8000 &
sudo blocking-io-check --pid $(pgrep -f uvicorn) -d 20 --summary --hide-dns
```

**While hitting `/bad`:**

```
14:02:33.481 pid= 40213 comm=uvicorn  fd=14 op=connect  dur=    12.300ms ret=0    flags=B--- peer=10.0.7.22:8080 verdict=STALL
14:02:34.702 pid= 40213 comm=uvicorn  fd=14 op=recvfrom dur=  1203.400ms ret=8192 flags=B--- peer=10.0.7.22:8080 verdict=STALL

=== summary (2841 events, 68 blocking, 68 stalls, 20.0s) ===
comm     pid    op        peer              count  block  stall     total       max       p50       p95       p99
uvicorn  40213  recvfrom  10.0.7.22:8080       34     34     34  40915.60  1289.100  1203.400  1281.700  1289.100
```

`flags=B---` on a socket talking to the upstream: no `O_NONBLOCK`, not in epoll.
`requests` created its own socket and the event loop knows nothing about it. 40
seconds of loop time lost in a 20-second window (multiple concurrent requests all
serialized behind each other).

**While hitting `/good`,** the same peer looks completely different:

```
14:05:11.220 pid= 40213 comm=uvicorn  fd=15 op=recvfrom dur=     0.019ms ret=-11  flags=NE-- peer=10.0.7.22:8080 verdict=OK
14:05:11.221 pid= 40213 comm=uvicorn  fd=-1 op=epoll_wait dur= 512.400ms ret=1    flags=?--- peer=-              verdict=IDLE
```

Same upstream, same latency in wall-clock terms — but the loop stayed free the
whole time. **`epoll_wait` is where the waiting belongs.**

**The fix** is to replace `requests.get` with the `httpx` call (or wrap it in
`run_in_executor`, which moves the blocking read to a worker thread where this
tool will correctly stop calling it a stall). Re-run and confirm the `STALL` rows
are gone.

### A second case: blocking DNS

`getaddrinfo` is synchronous in CPython, so name resolution blocks the loop even
in otherwise-correct async code. Run **without** `--hide-dns` to see it:

```
op=sendto   dur=     0.031ms ret=42   flags=B--- peer=10.0.0.53:53 verdict=OK
op=recvfrom dur=  5012.400ms ret=-11  flags=B--- peer=10.0.0.53:53 verdict=STALL
```

A five-second DNS timeout, and it will not appear in any Python-level trace.

## Limitations and caveats

Read this section before trusting a result.

- **musl / static binaries**: uprobes attach to glibc symbols. On Alpine or with
  statically-linked interpreters, flag tracking degrades to `?` (unknown).
  Duration measurement still works, since it comes from tracepoints.
- **`comm` is 15 bytes**: process names are truncated by the kernel, so
  `--process-name` is effectively a 15-byte exact match. The tool rejects longer
  names rather than silently never matching.
- **Per-`(pid,fd)` state is racy**: `dup`/`dup2`, fds inherited across `fork`, and
  rapid fd reuse can attribute state to the wrong socket. `close` cleanup makes
  this much rarer than it used to be, but it is not eliminated.
- **`/proc` seeding covers only fds open at startup**, and only reliably in
  `--pid` mode. Sockets created later are covered by the `socket`/`accept4`/
  `fcntl` probes instead.
- **`read`/`write`/`readv`/`writev` are only reported for fds in `peer_map`** —
  i.e. sockets seen by `connect`/`accept4`. Pre-existing connections established
  before the tracer attached, and non-socket fds, are not reported for these ops.
- **Duration is enter→exit wall time**, which includes preemption, page faults,
  and CPU scheduling delay — not purely I/O wait.
- **Events can be dropped** under very high syscall rates; the perf buffer is
  finite. Use `--min-latency` to reduce pressure.
- **Do not run this permanently in production.** It is a diagnostic tool. Attach,
  measure with `-d`, detach.
- **Containers**: requires host-level privileges, and PIDs are host PIDs.
- **The eBPF program is not compile-checked in CI** (see Development).

## Development

```bash
uv sync --group dev
uv run pytest                  # no root, no BCC, no Linux needed
uv run pytest --cov=blockingio
uv run ruff check . && uv run ruff format .
uv run mypy
```

### Architectural invariant

**Every module except `runtime.py` is pure and does not import `bcc`.** That is
what lets the whole test suite run on macOS, and it is enforced by a macOS job in
CI. Do not add a top-level `import bcc` anywhere — `runtime.py` imports it inside
a function on purpose.

The decode boundary is `Event.from_ctypes()`. Downstream code (`filters`,
`output`, `summary`) sees only the `Event` dataclass, never ctypes, which is why
most tests are plain Python.

### Adding a traced syscall

Two places must agree:

1. `blockingio/bpf/trace.bpf.c` — add `#define OP_<NAME> <n>` and the
   `sys_enter_*` / `sys_exit_*` probe pair
2. `blockingio/event.py` — append the label to `OPS` at index `n`

`tests/test_bpf_consistency.py` enforces the agreement by parsing the C source,
and also verifies that the `struct io_evt_t` field order still matches the ctypes
mirror. A mismatch there produces silently garbled output, so that test is the
most important one in the suite.

### The BPF program is not compile-checked

`trace.bpf.c` cannot be validated in CI. It uses macros that only exist inside
BCC's clang rewriter (`BPF_HASH`, `TRACEPOINT_PROBE`), includes kernel headers
resolved from BCC's bundle, and contains `{PLACEHOLDER}` tokens that make it not
valid C until Python substitutes them. GitHub-hosted runners have no kernel
probes either.

What CI does instead: the two text-level consistency tests above. **Smoke-test on
a real Linux host before releasing.**

### Migrating from 0.1.x

`sudo uv run blocking_io_check.py` still works — it is now a thin shim. Prefer
`blocking-io-check` or `python -m blockingio`. Note that events now report at
syscall *exit* rather than entry, so ordering is completion order, and the default
`--min-latency 1.0` means you see far less output than before; pass
`--min-latency 0` for the old firehose.

## License

MIT — see [LICENSE](LICENSE).
