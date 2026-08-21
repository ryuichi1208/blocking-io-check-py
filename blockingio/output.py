"""出力フォーマッタとシンク。

テキストは全フィールドを key=value に保つので grep しやすい。
verdict を最後に置くので `| grep verdict=STALL` と `| awk '{print $NF}'` の
両方が効く。
"""

from __future__ import annotations

import json
import os
import sys
from datetime import UTC, datetime
from typing import IO, Protocol

from .event import Event, Verdict

# JSON のキー集合。minor version 内では追加のみ。
JSON_KEYS = (
    "ts_ns",
    "time",
    "pid",
    "tid",
    "comm",
    "fd",
    "op",
    "op_code",
    "duration_ns",
    "duration_ms",
    "ret",
    "nonblock",
    "via_epoll",
    "msg_dontwait",
    "family",
    "family_name",
    "peer",
    "peer_addr",
    "peer_port",
    "verdict",
)

_COLORS = {
    Verdict.OK: "",
    Verdict.IDLE: "\033[2m",
    Verdict.WARN: "\033[33m",
    Verdict.STALL: "\033[31m",
}
_RESET = "\033[0m"


def want_color(stream: IO[str], no_color: bool) -> bool:
    if no_color or os.environ.get("NO_COLOR") is not None:
        return False
    return hasattr(stream, "isatty") and stream.isatty()


class Clock:
    """BPF の monotonic な ktime を壁時計へ換算する。

    起動時に一度だけ両方を読み、以降は差分で換算する。
    """

    def __init__(self, wall_ns: int, mono_ns: int) -> None:
        self._wall_ns = wall_ns
        self._mono_ns = mono_ns

    @classmethod
    def now(cls) -> Clock:
        import time

        return cls(wall_ns=time.time_ns(), mono_ns=time.monotonic_ns())

    def to_wall_ns(self, ktime_ns: int) -> int:
        return self._wall_ns + (ktime_ns - self._mono_ns)

    def to_datetime(self, ktime_ns: int) -> datetime:
        return datetime.fromtimestamp(self.to_wall_ns(ktime_ns) / 1e9, tz=UTC)


class Formatter(Protocol):
    def format(self, e: Event) -> str: ...


def flags_field(e: Event) -> str:
    """NEDT のコンパクトなビットフィールド。固定幅 4 なので桁が崩れない。"""
    return "".join(
        (
            "N" if e.nonblock == 1 else ("?" if e.nonblock < 0 else "B"),
            "E" if e.via_epoll else "-",
            "D" if e.msg_dontwait else "-",
            "T" if e.comm_truncated else "-",
        )
    )


class TextFormatter:
    def __init__(self, clock: Clock, color: bool = False) -> None:
        self._clock = clock
        self._color = color

    def format(self, e: Event) -> str:
        ts = self._clock.to_datetime(e.ts_ns).strftime("%H:%M:%S.%f")[:-3]
        verdict = e.verdict.label
        if self._color:
            verdict = f"{_COLORS[e.verdict]}{verdict}{_RESET}"
        return (
            f"{ts} pid={e.pid:>6} comm={e.comm:<16} fd={e.fd:<4} "
            f"op={e.op:<10} dur={e.duration_ms:>10.3f}ms ret={e.ret:<6} "
            f"flags={flags_field(e)} peer={e.peer:<24} verdict={verdict}"
        )


class JsonlFormatter:
    def __init__(self, clock: Clock) -> None:
        self._clock = clock

    def format(self, e: Event) -> str:
        from .event import family_name

        obj = {
            "ts_ns": e.ts_ns,
            "time": self._clock.to_datetime(e.ts_ns).isoformat().replace("+00:00", "Z"),
            "pid": e.pid,
            "tid": e.tid,
            "comm": e.comm,
            "fd": e.fd,
            "op": e.op,
            "op_code": e.op_code,
            "duration_ns": e.duration_ns,
            "duration_ms": round(e.duration_ms, 6),
            "ret": e.ret,
            "nonblock": e.nonblock,
            "via_epoll": e.via_epoll,
            "msg_dontwait": e.msg_dontwait,
            "family": e.family,
            "family_name": family_name(e.family),
            "peer": e.peer,
            "peer_addr": e.peer_addr,
            "peer_port": e.peer_port,
            "verdict": e.verdict.label,
        }
        return json.dumps(obj, separators=(",", ":"))


class EventSink:
    """出力先を所有する。-o 指定時はファイル、既定は stdout。"""

    def __init__(self, formatter: Formatter, path: str | None = None) -> None:
        self._formatter = formatter
        self._path = path
        self._fh: IO[str] | None = None
        self._owned = False

    def __enter__(self) -> EventSink:
        if self._path:
            # 行バッファなので tail -f が効く。
            self._fh = open(self._path, "w", buffering=1)
            self._owned = True
        else:
            self._fh = sys.stdout
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    def emit(self, e: Event) -> None:
        assert self._fh is not None
        self._fh.write(self._formatter.format(e) + "\n")

    def close(self) -> None:
        if self._fh is not None:
            if self._owned:
                self._fh.close()
            else:
                self._fh.flush()
            self._fh = None
