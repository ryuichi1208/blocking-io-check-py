"""peer 整形、op ラベル、ctypes デコード境界。"""

import ctypes as ct
import socket

import pytest

from blockingio.event import (
    AF_NETLINK,
    OPS,
    Event,
    Verdict,
    family_name,
    format_peer,
    ipv4_ntoa,
    ipv6_ntoa,
    ntohs,
    op_label,
)
from tests.factories import ipv4_raw, make_raw


class TestHelpers:
    def test_ntohs_roundtrip(self):
        assert ntohs(socket.htons(5432)) == 5432

    def test_ipv4_ntoa_known_value(self):
        assert ipv4_ntoa(ipv4_raw("127.0.0.1")) == "127.0.0.1"

    def test_ipv4_ntoa_zero(self):
        assert ipv4_ntoa(ipv4_raw("0.0.0.0")) == "0.0.0.0"

    def test_ipv4_ntoa_broadcast(self):
        assert ipv4_ntoa(ipv4_raw("255.255.255.255")) == "255.255.255.255"

    def test_ipv6_ntoa_loopback(self):
        packed = socket.inet_pton(socket.AF_INET6, "::1")
        assert ipv6_ntoa(packed) == "::1"

    def test_ipv6_ntoa_accepts_ctypes_array(self):
        arr = (ct.c_ubyte * 16)(*socket.inet_pton(socket.AF_INET6, "2001:db8::1"))
        assert ipv6_ntoa(arr) == "2001:db8::1"


class TestFormatPeer:
    def test_af_inet(self):
        peer = format_peer(socket.AF_INET, socket.htons(5432), ipv4_raw("10.0.3.14"), b"\0" * 16)
        assert peer == "10.0.3.14:5432"

    def test_af_inet6_is_bracketed(self):
        packed = socket.inet_pton(socket.AF_INET6, "2001:db8::1")
        peer = format_peer(socket.AF_INET6, socket.htons(443), 0, packed)
        assert peer == "[2001:db8::1]:443"

    def test_af_netlink_shows_pid_and_groups(self):
        peer = format_peer(AF_NETLINK, socket.htons(3), 1234, b"\0" * 16)
        assert peer == "netlink(pid=1234, groups=3)"

    def test_family_zero_is_dash(self):
        assert format_peer(0, 0, 0, b"\0" * 16) == "-"

    def test_unknown_family_falls_back(self):
        # AF_UNIX = 1
        assert format_peer(1, 0, 0, b"\0" * 16) == "fam=1"


class TestFamilyName:
    @pytest.mark.parametrize(
        "family,expected",
        [
            (socket.AF_INET, "AF_INET"),
            (socket.AF_INET6, "AF_INET6"),
            (AF_NETLINK, "AF_NETLINK"),
            (0, "NONE"),
            (1, "AF_1"),
        ],
    )
    def test_names(self, family, expected):
        assert family_name(family) == expected


class TestOpLabel:
    def test_covers_all_known_codes(self):
        for i, name in enumerate(OPS):
            assert op_label(i) == name

    @pytest.mark.parametrize("op", [-1, 999, len(OPS)])
    def test_out_of_range_returns_opn(self, op):
        assert op_label(op) == f"op{op}"


class TestDecode:
    def test_from_ctypes_roundtrip(self):
        raw = make_raw(pid=4242, fd=9, op=1, duration_ns=1_203_400_000, ret=8192)
        e = Event.from_ctypes(raw)
        assert e.pid == 4242
        assert e.fd == 9
        assert e.op == "recvfrom"
        assert e.op_code == 1
        assert e.duration_ns == 1_203_400_000
        assert e.duration_ms == pytest.approx(1203.4)
        assert e.ret == 8192
        assert e.comm == "python3"
        assert e.peer == "10.0.3.14:5432"
        assert e.peer_addr == "10.0.3.14"
        assert e.peer_port == 5432

    def test_negative_ret_is_signed(self):
        # -EAGAIN は非ブロッキングが健全に動いている最も診断価値の高いイベント。
        e = Event.from_ctypes(make_raw(ret=-11))
        assert e.ret == -11

    def test_unknown_op_code_preserved(self):
        e = Event.from_ctypes(make_raw(op=99))
        assert e.op == "op99"
        assert e.op_code == 99

    def test_comm_truncation_detected(self):
        e = Event.from_ctypes(make_raw(comm=b"123456789012345"))
        assert e.comm_truncated is True

    def test_short_comm_not_flagged_truncated(self):
        assert Event.from_ctypes(make_raw(comm=b"python3")).comm_truncated is False

    def test_invalid_utf8_comm_does_not_raise(self):
        e = Event.from_ctypes(make_raw(comm=b"bad\xff\xfename"))
        assert isinstance(e.comm, str)

    def test_netlink_peer_parts_are_none(self):
        e = Event.from_ctypes(make_raw(family=AF_NETLINK, raddr4=99))
        assert e.peer_addr is None
        assert e.peer_port is None
        assert "netlink" in e.peer

    def test_ipv6_event(self):
        e = Event.from_ctypes(
            make_raw(family=socket.AF_INET6, addr6="2001:db8::1", rport=socket.htons(443))
        )
        assert e.peer == "[2001:db8::1]:443"
        assert e.peer_addr == "2001:db8::1"
        assert e.peer_port == 443

    def test_out_of_range_verdict_falls_back_to_ok(self):
        assert Event.from_ctypes(make_raw(verdict=77)).verdict is Verdict.OK

    @pytest.mark.parametrize(
        "verdict,expected",
        [
            (Verdict.OK, False),
            (Verdict.IDLE, False),
            (Verdict.WARN, True),
            (Verdict.STALL, True),
        ],
    )
    def test_is_blocking(self, verdict, expected):
        e = Event.from_ctypes(make_raw(verdict=int(verdict)))
        assert e.is_blocking is expected
