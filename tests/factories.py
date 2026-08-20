"""テスト用のイベント構築。本文に大量の位置引数を書かせないため。"""

from __future__ import annotations

import ctypes as ct
import socket
import struct

from blockingio.event import Event, IoEvt, Verdict


def ipv4_raw(addr: str) -> int:
    """ "10.0.3.14" -> raddr4 に入る値。event.ipv4_ntoa の逆変換。"""
    return socket.htonl(struct.unpack("!I", socket.inet_aton(addr))[0])


def _raddr6(addr: str):
    packed = socket.inet_pton(socket.AF_INET6, addr)
    return (ct.c_ubyte * 16)(*packed)


def make_raw(**overrides) -> IoEvt:
    kw = {
        "ts": 1_000_000_000,
        "duration_ns": 500_000,
        "ret": 8192,
        "pid": 4242,
        "tid": 4242,
        "comm": b"python3",
        "fd": 9,
        "op": 1,  # recvfrom
        "nonblock": 1,
        "via_epoll": 1,
        "msg_dontwait": 0,
        "verdict": int(Verdict.OK),
        "family": socket.AF_INET,
        "rport": socket.htons(5432),
        "raddr4": ipv4_raw("10.0.3.14"),
    }
    addr6 = overrides.pop("addr6", None)
    kw.update(overrides)
    raw = IoEvt(**kw)
    if addr6 is not None:
        raw.raddr6 = _raddr6(addr6)
    return raw


def make_event(**overrides) -> Event:
    """Event を直接作る。verdict などを上書きしたい場合に使う。"""
    raw_keys = {
        "ts",
        "duration_ns",
        "ret",
        "pid",
        "tid",
        "comm",
        "fd",
        "op",
        "nonblock",
        "via_epoll",
        "msg_dontwait",
        "verdict",
        "family",
        "rport",
        "raddr4",
        "addr6",
    }
    raw_over = {k: v for k, v in overrides.items() if k in raw_keys}
    post = {k: v for k, v in overrides.items() if k not in raw_keys}
    e = Event.from_ctypes(make_raw(**raw_over))
    if post:
        import dataclasses

        e = dataclasses.replace(e, **post)
    return e
