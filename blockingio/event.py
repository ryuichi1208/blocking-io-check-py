"""イベントのデコードと判定。

bcc に依存しないため、Linux 以外でも import / テストできる。
ctypes 構造体は blockingio/bpf/trace.bpf.c の struct io_evt_t の鏡像であり、
両者は必ず同時に編集する。フィールド順がずれると出力が静かに壊れる。
"""

from __future__ import annotations

import ctypes as ct
import socket
import struct
from dataclasses import dataclass
from enum import IntEnum

# socket.AF_NETLINK は Linux 専用で macOS には存在しない。
# テストを Linux 以外でも動かすため定数として持つ。
AF_NETLINK = 16

# raddr6 は生の bytes か ctypes の c_ubyte 配列のどちらかで渡ってくる。
Addr6 = bytes | ct.Array[ct.c_ubyte]

# op コードは trace.bpf.c の "// op codes:" コメントと一致させる。
# tests/test_ops.py がこの一致を機械的に検証する。
OPS: tuple[str, ...] = (
    "sendto",
    "recvfrom",
    "sendmsg",
    "recvmsg",
    "write",
    "read",
    "connect",
    "accept4",
    "close",
    "readv",
    "writev",
    "epoll_wait",
    "poll",
    "select",
    "openat",
    "fsync",
    "fdatasync",
)

# op の分類。待機系 (poll) は長くても正常なので verdict で別扱いする。
_WAIT_OPS = frozenset({"epoll_wait", "poll", "select"})
_FILE_OPS = frozenset({"openat", "fsync", "fdatasync"})

# nonblock の三値。マップに無い = 不明であって「ブロッキング」ではない。
NB_BLOCKING = 0
NB_NONBLOCK = 1
NB_UNKNOWN = -1


class Verdict(IntEnum):
    """判定。値は trace.bpf.c の V_* マクロと一致させる。"""

    OK = 0
    IDLE = 1
    WARN = 2
    STALL = 3

    @property
    def label(self) -> str:
        return self.name


class IoEvt(ct.Structure):
    """trace.bpf.c の struct io_evt_t の鏡像。順序を変えないこと。"""

    _fields_ = (
        ("ts", ct.c_ulonglong),
        ("duration_ns", ct.c_ulonglong),
        ("ret", ct.c_longlong),
        ("pid", ct.c_uint),
        ("tid", ct.c_uint),
        ("comm", ct.c_char * 16),
        ("fd", ct.c_int),
        ("op", ct.c_int),
        ("nonblock", ct.c_int),
        ("via_epoll", ct.c_int),
        ("msg_dontwait", ct.c_int),
        ("verdict", ct.c_int),
        ("family", ct.c_ushort),
        ("rport", ct.c_ushort),
        ("raddr4", ct.c_uint),
        ("raddr6", ct.c_ubyte * 16),
    )


def op_label(op: int) -> str:
    if 0 <= op < len(OPS):
        return OPS[op]
    return f"op{op}"


def op_is_wait(label: str) -> bool:
    return label in _WAIT_OPS


def op_is_file(label: str) -> bool:
    return label in _FILE_OPS


def ntohs(x: int) -> int:
    return socket.ntohs(x)


def ipv4_ntoa(n: int) -> str:
    return socket.inet_ntoa(struct.pack("!I", socket.ntohl(n)))


def ipv6_ntoa(b: Addr6) -> str:
    return socket.inet_ntop(socket.AF_INET6, bytes(b))


def format_peer(family: int, rport: int, raddr4: int, raddr6: Addr6) -> str:
    """peer の人間向け表現。スカラを受けるので構造体なしでテストできる。"""
    if family == socket.AF_INET:
        return f"{ipv4_ntoa(raddr4)}:{ntohs(rport)}"
    if family == socket.AF_INET6:
        return f"[{ipv6_ntoa(raddr6)}]:{ntohs(rport)}"
    if family == AF_NETLINK:
        return f"netlink(pid={raddr4}, groups={ntohs(rport)})"
    if family == 0:
        return "-"
    return f"fam={family}"


def peer_parts(
    family: int, rport: int, raddr4: int, raddr6: Addr6
) -> tuple[str | None, int | None]:
    """JSON 用に peer をアドレスとポートへ分解する。inet 以外は (None, None)。"""
    if family == socket.AF_INET:
        return ipv4_ntoa(raddr4), ntohs(rport)
    if family == socket.AF_INET6:
        return ipv6_ntoa(raddr6), ntohs(rport)
    return None, None


def family_name(family: int) -> str:
    if family == socket.AF_INET:
        return "AF_INET"
    if family == socket.AF_INET6:
        return "AF_INET6"
    if family == AF_NETLINK:
        return "AF_NETLINK"
    if family == 0:
        return "NONE"
    return f"AF_{family}"


def classify(
    *,
    nonblock: int,
    via_epoll: bool,
    msg_dontwait: bool,
    duration_ns: int,
    op: str,
    stall_ns: int,
    on_loop_thread: bool = True,
) -> Verdict:
    """このイベントがイベントループを止めたのかを判定する。

    規則: epoll に登録されていないブロッキング fd が閾値を超えたら STALL。
    それ以外はせいぜい WARN。

    nonblock が不明なときは決して STALL にしない。トレーサのアタッチ前に
    O_NONBLOCK が設定されていた場合に「自信を持って間違える」のを防ぐため。
    """
    # 待機系 syscall は長いのが正常。イベントループのアイドルであって障害ではない。
    if op_is_wait(op):
        return Verdict.IDLE

    # 明示的に待たない指定がある呼び出しはブロックしえない。
    if msg_dontwait:
        return Verdict.OK

    if nonblock == NB_NONBLOCK:
        # 非ブロッキング fd は原理上長く待たない。長いならカーネル/NIC 側の別要因。
        return Verdict.WARN if duration_ns >= stall_ns * 10 else Verdict.OK

    if nonblock == NB_UNKNOWN:
        return Verdict.OK

    # ここから下は nonblock == NB_BLOCKING（真にブロッキング）。
    if via_epoll:
        # epoll に登録済みなのにブロッキングというのは矛盾しており、状態追跡の
        # 取りこぼしの可能性がある。断定せず警告にとどめる。
        return Verdict.WARN

    if duration_ns < stall_ns:
        return Verdict.OK

    # ThreadPoolExecutor のワーカでのブロッキング I/O はそのスレッドの本来の仕事。
    # イベントループを回しているスレッドで起きたときだけ本物のストール。
    if not on_loop_thread:
        return Verdict.OK

    return Verdict.STALL


@dataclass(frozen=True, slots=True)
class Event:
    """デコード済みイベント。ctypes と下流の境界。"""

    ts_ns: int
    duration_ns: int
    ret: int
    pid: int
    tid: int
    comm: str
    comm_truncated: bool
    fd: int
    op_code: int
    op: str
    nonblock: int
    via_epoll: bool
    msg_dontwait: bool
    family: int
    rport: int
    peer: str
    peer_addr: str | None
    peer_port: int | None
    verdict: Verdict

    @classmethod
    def from_ctypes(cls, raw: IoEvt) -> Event:
        comm_raw = raw.comm
        comm = comm_raw.decode(errors="replace")
        label = op_label(raw.op)
        addr, port = peer_parts(raw.family, raw.rport, raw.raddr4, raw.raddr6)
        try:
            verdict = Verdict(raw.verdict)
        except ValueError:
            verdict = Verdict.OK
        return cls(
            ts_ns=raw.ts,
            duration_ns=raw.duration_ns,
            ret=raw.ret,
            pid=raw.pid,
            tid=raw.tid,
            comm=comm,
            # comm は 15 バイト + NUL。ちょうど 15 バイトなら切り詰められた可能性がある。
            comm_truncated=len(comm_raw) >= 15,
            fd=raw.fd,
            op_code=raw.op,
            op=label,
            nonblock=raw.nonblock,
            via_epoll=bool(raw.via_epoll),
            msg_dontwait=bool(raw.msg_dontwait),
            family=raw.family,
            rport=raw.rport,
            peer=format_peer(raw.family, raw.rport, raw.raddr4, raw.raddr6),
            peer_addr=addr,
            peer_port=port,
            verdict=verdict,
        )

    @property
    def is_blocking(self) -> bool:
        return self.verdict in (Verdict.WARN, Verdict.STALL)

    @property
    def duration_ms(self) -> float:
        return self.duration_ns / 1_000_000
