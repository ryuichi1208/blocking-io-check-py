"""環境チェック、BPF ロード、/proc スキャン。

bcc に触る唯一のモジュール。`from bcc import BPF` は必ず関数の中で行い、
このモジュールの import 自体は macOS でも成功させる。そうでないとテストが
Linux 以外で動かなくなる。
"""

from __future__ import annotations

import ctypes as ct
import glob
import os
import platform
import sys

MIN_KERNEL = (4, 9)
O_NONBLOCK = 0o4000
COMM_MAX = 15  # comm は 15 バイト + NUL


class SetupError(Exception):
    """セットアップ失敗。cli が exit code 1 に変換する。"""


class KeyT(ct.Structure):
    """trace.bpf.c の struct key_t の鏡像。

    u32 + int は自然アライメントでパディングが入らないので _pack_ は不要。
    """

    _fields_ = (("pid", ct.c_uint), ("fd", ct.c_int))


def parse_kernel_version(release: str) -> tuple[int, int] | None:
    """ "5.15.0-91-generic" -> (5, 15)。解釈できなければ None。"""
    head = release.split("-")[0]
    parts = head.split(".")
    try:
        major = int(parts[0])
    except (ValueError, IndexError):
        return None
    minor = 0
    if len(parts) > 1:
        try:
            minor = int(parts[1])
        except ValueError:
            return None
    return major, minor


def check_environment(min_kernel: tuple[int, int] = MIN_KERNEL) -> None:
    if platform.system() != "Linux":
        raise SetupError("only Linux is supported")
    release = platform.release()
    ver = parse_kernel_version(release)
    if ver is None:
        raise SetupError(f"unknown kernel version: {release}")
    if ver < min_kernel:
        raise SetupError(
            f"kernel {ver[0]}.{ver[1]} is too old (need {min_kernel[0]}.{min_kernel[1]}+)"
        )


def find_libc() -> str | None:
    """uprobe を張る libc を探す。アーキテクチャに応じて候補を組む。"""
    machine = platform.machine()
    patterns = [
        f"/lib/{machine}-linux-gnu/libc.so.6",
        f"/usr/lib/{machine}-linux-gnu/libc.so.6",
        "/lib64/libc.so.6",
        "/usr/lib64/libc.so.6",
        "/lib/libc.so.6",
        "/usr/lib/libc.so.6",
    ]
    for p in patterns:
        if os.path.exists(p):
            return p
    # musl は libc とローダが同一オブジェクト。フラグ追跡は期待できないが
    # duration の計測は tracepoint 側なので動く。
    for p in sorted(glob.glob("/lib/ld-musl-*.so.1")):
        if os.path.exists(p):
            return p
    from ctypes.util import find_library

    found = find_library("c")
    if found and os.path.isabs(found):
        return found
    return None


def bpf_source_path() -> str:
    """同梱の trace.bpf.c を解決する。cwd に依存しない。"""
    from importlib.resources import files

    return str(files("blockingio") / "bpf" / "trace.bpf.c")


def escape_c_string(s: str) -> str:
    """C 文字列リテラルへ安全に埋め込む。

    生の値を埋めるとプロセス名にクォートを混ぜてソース injection ができる。
    """
    out = []
    for ch in s:
        if ch in ('"', "\\"):
            out.append("\\" + ch)
        elif ch == "\n":
            out.append("\\n")
        elif 0x20 <= ord(ch) < 0x7F:
            out.append(ch)
        else:
            raise SetupError(f"process name contains unsupported character: {ch!r}")
    return "".join(out)


def substitute(
    src: str,
    *,
    pid: int | None,
    process_name: str,
    min_latency_ns: int,
    stall_latency_ns: int,
    trace_file_io: bool,
    trace_wait: bool,
    all_threads: bool,
) -> str:
    """BPF ソースのプレースホルダを埋める。

    未使用プローブを不活性ではなく「不在」にする。BCC は見つけた
    TRACEPOINT_PROBE を全てアタッチするので、不活性なプローブでも syscall
    ごとにカーネル側のコストを払う。コンパイル時排除だけがゼロコスト。
    """
    if len(process_name.encode()) > COMM_MAX:
        raise SetupError(
            f"process name {process_name!r} is longer than {COMM_MAX} bytes; "
            f"the kernel truncates comm so it would never match"
        )
    use_pid = pid is not None
    out = src
    out = out.replace("{USE_PID_FILTER}", "1" if use_pid else "0")
    out = out.replace("{TARGET_PID}", str(pid if use_pid else 0))
    out = out.replace("{TARGET_COMM}", escape_c_string(process_name))
    out = out.replace("{MIN_LATENCY_NS}", str(min_latency_ns))
    out = out.replace("{STALL_LATENCY_NS}", str(stall_latency_ns))
    out = out.replace("{TRACE_FILE_IO}", "1" if trace_file_io else "0")
    out = out.replace("{TRACE_WAIT}", "1" if trace_wait else "0")
    out = out.replace("{REQUIRE_LOOP_THREAD}", "0" if all_threads else "1")
    return out


def parse_fdinfo_flags(text: str) -> int | None:
    """/proc/<pid>/fdinfo/<fd> の "flags:\\t02004002" から 8 進フラグを取る。"""
    for line in text.splitlines():
        if line.startswith("flags:"):
            try:
                return int(line.split(":", 1)[1].strip(), 8)
            except ValueError:
                return None
    return None


def _read_text(path: str) -> str | None:
    try:
        with open(path) as f:
            return f.read()
    except OSError:
        return None


def scan_pid_fds(pid: int, read_file=_read_text, listdir=os.listdir) -> dict[int, bool]:
    """開いている fd の O_NONBLOCK 状態を読む。{fd: nonblock}。

    これがトレーサのアタッチ前に設定されたフラグを復元する仕組みで、
    asyncio が全てブロッキング扱いされる誤検知の主たる修正。
    """
    out: dict[int, bool] = {}
    try:
        names = listdir(f"/proc/{pid}/fd")
    except OSError:
        return out
    for name in names:
        if not name.isdigit():
            continue
        fd = int(name)
        text = read_file(f"/proc/{pid}/fdinfo/{fd}")
        if text is None:
            continue  # レース: 既に close された
        flags = parse_fdinfo_flags(text)
        if flags is not None:
            out[fd] = bool(flags & O_NONBLOCK)
    return out


def pids_for_comm(name: str, read_file=_read_text) -> list[int]:
    """comm が一致するプロセスを探す。--process-name モードの seeding 用。"""
    found = []
    for path in glob.glob("/proc/[0-9]*/comm"):
        text = read_file(path)
        if text is None:
            continue
        if text.strip() == name[:COMM_MAX]:
            try:
                found.append(int(path.split("/")[2]))
            except (ValueError, IndexError):
                continue
    return found


def seed_fd_nonblock(table, pid: int, fd_states: dict[int, bool]) -> int:
    """fdinfo で読んだ状態を BPF マップへ流し込む。"""
    n = 0
    for fd, nb in fd_states.items():
        table[KeyT(pid=pid, fd=fd)] = ct.c_ubyte(1 if nb else 0)
        n += 1
    return n


def import_bpf():
    """bcc を遅延 import する。ここだけが Linux/bcc に依存する。"""
    try:
        from bcc import BPF
    except ImportError as exc:
        raise SetupError(
            "the bcc Python module is not available. BCC is distro-packaged and "
            "cannot be installed from PyPI:\n"
            "  Ubuntu/Debian: sudo apt install python3-bpfcc bpfcc-tools\n"
            "  Fedora/RHEL:   sudo dnf install python3-bcc bcc-tools\n"
            "  Arch:          sudo pacman -S python-bcc bcc-tools\n"
            "Note: the PyPI package named 'bcc' is an unrelated project."
        ) from exc
    return BPF


def require_root() -> None:
    if hasattr(os, "geteuid") and os.geteuid() != 0:
        raise SetupError("root privileges are required for eBPF (try sudo)")


def warn(msg: str) -> None:
    print(f"warning: {msg}", file=sys.stderr)
