"""CLI: argparse、配線、ポーリングループ、ライフサイクル。"""

from __future__ import annotations

import argparse
import ctypes as ct
import signal
import sys
import time
from contextlib import AbstractContextManager, nullcontext

from . import __version__, runtime
from .event import OPS, Event, IoEvt, Verdict
from .filters import DisplayFilter
from .output import Clock, EventSink, JsonlFormatter, TextFormatter, want_color
from .summary import GROUP_FIELDS, Aggregator

EXIT_OK = 0
EXIT_SETUP = 1
EXIT_BLOCKING = 3

DEFAULT_MIN_LATENCY_MS = 1.0
DEFAULT_STALL_LATENCY_MS = 50.0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="blocking-io-check",
        description="Detect blocking I/O in Python applications using eBPF",
    )
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")

    target = p.add_argument_group("target selection")
    target.add_argument(
        "-p",
        "--process-name",
        default="python3",
        help="target process name (comm), default: python3",
    )
    target.add_argument(
        "--pid",
        type=int,
        help="filter by specific PID (overrides process-name filter)",
    )
    target.add_argument(
        "-b",
        "--bpf-file",
        help="path to eBPF C source (default: the bundled trace.bpf.c)",
    )

    scope = p.add_argument_group("tracing scope")
    scope.add_argument(
        "--min-latency",
        type=float,
        default=DEFAULT_MIN_LATENCY_MS,
        metavar="MS",
        help=(
            "only report I/O that took at least this long, in milliseconds "
            f"(default: {DEFAULT_MIN_LATENCY_MS}; use 0 to report everything)"
        ),
    )
    scope.add_argument(
        "--stall-latency",
        type=float,
        default=DEFAULT_STALL_LATENCY_MS,
        metavar="MS",
        help=(
            "blocking I/O at least this slow is reported as a STALL "
            f"(default: {DEFAULT_STALL_LATENCY_MS}). Independent of --min-latency, "
            "which only controls what is displayed."
        ),
    )
    scope.add_argument(
        "--file-io",
        action="store_true",
        help="also trace file I/O (openat/fsync/fdatasync); noisy",
    )
    scope.add_argument(
        "--no-include-wait",
        dest="include_wait",
        action="store_false",
        help="do not trace waiting syscalls (epoll_wait/poll/select)",
    )
    scope.add_argument(
        "--all-threads",
        action="store_true",
        help=(
            "report stalls on any thread, not just event-loop threads "
            "(by default, blocking I/O on executor threads is not a stall)"
        ),
    )
    scope.add_argument(
        "--op",
        help="comma-separated list of ops to show (e.g. recvfrom,read)",
    )
    scope.add_argument("--hide-dns", action="store_true", help="hide port 53 traffic")
    scope.add_argument("--hide-netlink", action="store_true", help="hide AF_NETLINK traffic")
    scope.add_argument(
        "--only-blocking",
        action="store_true",
        help="only show events with verdict WARN or STALL",
    )

    out = p.add_argument_group("output")
    out.add_argument("--json", action="store_true", help="emit JSON Lines")
    out.add_argument("-o", "--output", metavar="FILE", help="write events to FILE")
    out.add_argument("--no-color", action="store_true", help="disable colored output")
    out.add_argument("--summary", action="store_true", help="print a summary on exit")
    out.add_argument(
        "--summary-only",
        action="store_true",
        help="print only the summary, suppressing per-event output",
    )
    out.add_argument(
        "--group-by",
        choices=sorted(GROUP_FIELDS),
        default="peer",
        help="summary grouping key (default: peer)",
    )
    out.add_argument("--top", type=int, default=20, metavar="N", help="summary rows to show")

    life = p.add_argument_group("lifecycle")
    life.add_argument(
        "-d",
        "--duration",
        type=float,
        metavar="SECONDS",
        help="stop tracing after this many seconds",
    )
    life.add_argument(
        "--fail-on-blocking",
        action="store_true",
        help=f"exit with status {EXIT_BLOCKING} if any blocking I/O was detected",
    )
    return p


def resolve_ops(spec: str | None) -> frozenset[str] | None:
    if not spec:
        return None
    wanted = {s.strip() for s in spec.split(",") if s.strip()}
    unknown = wanted - set(OPS)
    if unknown:
        raise runtime.SetupError(
            f"unknown op(s): {', '.join(sorted(unknown))}. Valid ops: {', '.join(OPS)}"
        )
    return frozenset(wanted)


def exit_code(agg: Aggregator | None, *, fail_on_blocking: bool) -> int:
    """終了コードを決める。

    既定では検出しても 0 を返す。非ゼロを既定にすると対話利用や && の連鎖を
    壊すため、CI ゲートは明示的なオプトインにしている。
    """
    if fail_on_blocking and agg is not None and agg.total_blocking:
        return EXIT_BLOCKING
    return EXIT_OK


def read_op_totals(bpf) -> int:
    """BPF 側の正確な総件数を読む。間引き前に数えているので表示件数より多い。"""
    try:
        return sum(v.value for v in bpf["op_stats"].values())
    except Exception:
        # 集計はベストエフォート。読めなくても本体の動作は止めない。
        return 0


def make_handler(sink: EventSink | None, flt: DisplayFilter, agg: Aggregator | None):
    """perf buffer コールバック。デコード -> 述語 -> 集計 -> 出力。"""

    def handler(cpu, data, size):
        raw = ct.cast(data, ct.POINTER(IoEvt)).contents
        e = Event.from_ctypes(raw)
        if not flt.allows(e):
            return
        if agg is not None:
            agg.add(e)
        if sink is not None:
            sink.emit(e)

    return handler


def _seed_nonblock_state(bpf, args) -> None:
    """トレーサのアタッチ前に設定された O_NONBLOCK を /proc から復元する。

    これが無いと asyncio のソケットが全てブロッキング扱いになる。
    """
    table = bpf["fd_nonblock"]
    pids = [args.pid] if args.pid is not None else runtime.pids_for_comm(args.process_name)
    total = 0
    for pid in pids:
        states = runtime.scan_pid_fds(pid)
        total += runtime.seed_fd_nonblock(table, pid, states)
    if pids and not total:
        runtime.warn(
            "could not read any fd state from /proc; "
            "sockets whose flags were set before attach may read as unknown"
        )
    return None


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    # --json のときは stdout を純粋な JSONL に保つため診断を stderr へ。
    diag = sys.stderr if (args.json and not args.output) else sys.stdout

    try:
        ops = resolve_ops(args.op)
        runtime.check_environment()
        runtime.require_root()
        BPF = runtime.import_bpf()

        bpf_file = args.bpf_file or runtime.bpf_source_path()
        try:
            with open(bpf_file) as f:
                src = f.read()
        except OSError as exc:
            raise runtime.SetupError(f"cannot read BPF source {bpf_file}: {exc}") from exc

        min_latency_ns = int(args.min_latency * 1_000_000)
        src = runtime.substitute(
            src,
            pid=args.pid,
            process_name=args.process_name,
            min_latency_ns=min_latency_ns,
            stall_latency_ns=int(args.stall_latency * 1_000_000),
            trace_file_io=args.file_io,
            trace_wait=args.include_wait,
            all_threads=args.all_threads,
        )

        libc = runtime.find_libc()
        if not libc:
            raise runtime.SetupError("could not locate libc for uprobes")

        bpf = BPF(text=src)
        # tracepoint のアタッチは BPF() 構築時に済んでいるので小さな窓は残るが、
        # 全イベントに lookup を足すゲート方式に見合う利益はない。
        _seed_nonblock_state(bpf, args)

        bpf.attach_uprobe(name=libc, sym="fcntl", fn_name="uprobe_fcntl")
        bpf.attach_uretprobe(name=libc, sym="fcntl", fn_name="uretprobe_fcntl")
        bpf.attach_uprobe(name=libc, sym="ioctl", fn_name="uprobe_ioctl")
        bpf.attach_uprobe(name=libc, sym="epoll_ctl", fn_name="uprobe_epoll_ctl")
    except runtime.SetupError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_SETUP

    clock = Clock.now()
    flt = DisplayFilter(
        hide_dns=args.hide_dns,
        hide_netlink=args.hide_netlink,
        ops=ops,
        min_verdict=Verdict.WARN if args.only_blocking else None,
    )
    agg = (
        Aggregator(group_by=args.group_by)
        if (args.summary or args.summary_only or args.fail_on_blocking)
        else None
    )

    formatter = (
        JsonlFormatter(clock)
        if args.json
        else TextFormatter(clock, color=want_color(sys.stdout, args.no_color))
    )

    stop = False

    def request_stop(*_: object) -> None:
        nonlocal stop
        stop = True

    signal.signal(signal.SIGINT, request_stop)
    signal.signal(signal.SIGTERM, request_stop)

    target = f"PID {args.pid}" if args.pid is not None else f"process '{args.process_name}'"
    limit = f" for {args.duration}s" if args.duration else ""
    print(
        f"Tracing blocking I/O for {target}{limit} "
        f"(showing >={args.min_latency}ms, stall >={args.stall_latency}ms)… "
        f"Ctrl-C to stop",
        file=diag,
    )

    started = time.monotonic()
    deadline = started + args.duration if args.duration else None
    # --summary-only ではイベントを出力しないのでシンクを持たない。
    sink_cm: AbstractContextManager[EventSink | None] = (
        nullcontext() if args.summary_only else EventSink(formatter, args.output)
    )

    try:
        with sink_cm as sink:
            bpf["events"].open_perf_buffer(make_handler(sink, flt, agg))
            while not stop:
                # timeout を付けないとアイドルな対象で -d が発火せず
                # SIGTERM も拾えない。
                bpf.perf_buffer_poll(timeout=200)
                if deadline and time.monotonic() >= deadline:
                    break
    except KeyboardInterrupt:
        pass
    finally:
        elapsed = time.monotonic() - started
        if agg is not None and (args.summary or args.summary_only):
            print(agg.render(top=args.top, elapsed_s=elapsed), file=diag)
            # op_stats は閾値で間引く前に数えているので総数が正確。
            # 「表示されなかった分」を示して、silent truncation を避ける。
            traced = read_op_totals(bpf)
            if traced:
                hidden = traced - agg.total_events
                print(
                    f"traced {traced} I/O operations in total; "
                    f"{max(hidden, 0)} below the {args.min_latency}ms display "
                    f"threshold were not shown",
                    file=diag,
                )

    return exit_code(agg, fail_on_blocking=args.fail_on_blocking)


if __name__ == "__main__":
    sys.exit(main())
