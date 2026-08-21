"""テキスト / JSON 出力とシンク。"""

import io
import json

import pytest

from blockingio.event import Verdict
from blockingio.output import (
    JSON_KEYS,
    Clock,
    EventSink,
    JsonlFormatter,
    TextFormatter,
    flags_field,
    want_color,
)
from tests.factories import make_event

CLOCK = Clock(wall_ns=1_700_000_000_000_000_000, mono_ns=1_000_000_000)


class TestFlagsField:
    def test_nonblocking_epoll(self):
        assert flags_field(make_event(nonblock=1, via_epoll=1)) == "NE--"

    def test_blocking_no_epoll(self):
        assert flags_field(make_event(nonblock=0, via_epoll=0)) == "B---"

    def test_unknown_state(self):
        assert flags_field(make_event(nonblock=-1, via_epoll=0)) == "?---"

    def test_dontwait(self):
        assert flags_field(make_event(nonblock=1, via_epoll=0, msg_dontwait=1)) == "N-D-"

    def test_truncated_comm(self):
        e = make_event(nonblock=0, via_epoll=0, comm=b"123456789012345")
        assert flags_field(e) == "B--T"

    def test_always_four_chars(self):
        for nb in (-1, 0, 1):
            for epoll in (0, 1):
                for dw in (0, 1):
                    e = make_event(nonblock=nb, via_epoll=epoll, msg_dontwait=dw)
                    assert len(flags_field(e)) == 4


class TestTextFormatter:
    def test_is_single_line(self):
        line = TextFormatter(CLOCK).format(make_event())
        assert "\n" not in line

    def test_contains_key_value_tokens(self):
        line = TextFormatter(CLOCK).format(make_event())
        for key in ("pid=", "comm=", "fd=", "op=", "dur=", "ret=", "flags=", "peer=", "verdict="):
            assert key in line

    def test_verdict_is_last_token(self):
        # `| awk '{print $NF}'` が効くことの担保。
        line = TextFormatter(CLOCK).format(make_event(verdict=int(Verdict.STALL)))
        assert line.split()[-1] == "verdict=STALL"

    def test_long_comm_does_not_break_line(self):
        line = TextFormatter(CLOCK).format(make_event(comm=b"123456789012345"))
        assert "\n" not in line
        assert "123456789012345" in line

    def test_color_wraps_only_verdict(self):
        line = TextFormatter(CLOCK, color=True).format(make_event(verdict=int(Verdict.STALL)))
        assert "\033[31m" in line
        assert "\033[0m" in line
        assert line.count("\033[0m") == 1

    def test_no_color_by_default(self):
        line = TextFormatter(CLOCK).format(make_event(verdict=int(Verdict.STALL)))
        assert "\033" not in line

    def test_duration_rendered_in_ms(self):
        line = TextFormatter(CLOCK).format(make_event(duration_ns=1_203_400_000))
        assert "1203.400ms" in line


class TestWantColor:
    def test_disabled_when_not_tty(self):
        assert want_color(io.StringIO(), no_color=False) is False

    def test_disabled_by_flag(self, monkeypatch):
        monkeypatch.delenv("NO_COLOR", raising=False)

        class Tty(io.StringIO):
            def isatty(self):
                return True

        assert want_color(Tty(), no_color=True) is False

    def test_disabled_by_no_color_env(self, monkeypatch):
        monkeypatch.setenv("NO_COLOR", "1")

        class Tty(io.StringIO):
            def isatty(self):
                return True

        assert want_color(Tty(), no_color=False) is False

    def test_enabled_on_tty(self, monkeypatch):
        monkeypatch.delenv("NO_COLOR", raising=False)

        class Tty(io.StringIO):
            def isatty(self):
                return True

        assert want_color(Tty(), no_color=False) is True


class TestJsonlFormatter:
    def obj(self, **kw):
        return json.loads(JsonlFormatter(CLOCK).format(make_event(**kw)))

    def test_exact_key_set(self):
        # スキーマの固定。キー名の取り違えを検出する。
        assert set(self.obj()) == set(JSON_KEYS)

    def test_key_order_is_documented_order(self):
        line = JsonlFormatter(CLOCK).format(make_event())
        obj = json.loads(line, object_pairs_hook=list)
        assert [k for k, _ in obj] == list(JSON_KEYS)

    def test_booleans_are_bools(self):
        o = self.obj(via_epoll=1, msg_dontwait=1)
        assert o["via_epoll"] is True
        assert o["msg_dontwait"] is True

    def test_nonblock_is_tristate_int_not_bool(self):
        # 三値なので bool にできない。unknown を表現する必要がある。
        assert self.obj(nonblock=-1)["nonblock"] == -1
        assert self.obj(nonblock=0)["nonblock"] == 0
        assert self.obj(nonblock=1)["nonblock"] == 1

    def test_one_object_per_line(self):
        line = JsonlFormatter(CLOCK).format(make_event())
        assert "\n" not in line
        json.loads(line)

    def test_netlink_peer_addr_is_null(self):
        from blockingio.event import AF_NETLINK

        o = self.obj(family=AF_NETLINK)
        assert o["peer_addr"] is None
        assert o["peer_port"] is None
        assert o["peer"].startswith("netlink(")

    def test_unknown_op_code_preserved(self):
        o = self.obj(op=99)
        assert o["op"] == "op99"
        assert o["op_code"] == 99

    def test_verdict_is_label(self):
        assert self.obj(verdict=int(Verdict.STALL))["verdict"] == "STALL"

    def test_time_is_iso8601_zulu(self):
        assert self.obj()["time"].endswith("Z")

    def test_ascii_only(self):
        line = JsonlFormatter(CLOCK).format(make_event(comm="日本".encode()))
        line.encode("ascii")  # 例外が出なければ OK


class TestEventSink:
    def test_writes_to_file(self, tmp_path):
        path = tmp_path / "out.jsonl"
        with EventSink(JsonlFormatter(CLOCK), str(path)) as sink:
            sink.emit(make_event())
            sink.emit(make_event(fd=11))
        lines = path.read_text().strip().splitlines()
        assert len(lines) == 2
        assert json.loads(lines[1])["fd"] == 11

    def test_writes_to_stdout_when_no_path(self, capsys):
        with EventSink(TextFormatter(CLOCK)) as sink:
            sink.emit(make_event())
        assert "verdict=" in capsys.readouterr().out

    def test_does_not_close_stdout(self, capsys):
        import sys

        with EventSink(TextFormatter(CLOCK)) as sink:
            sink.emit(make_event())
        assert not sys.stdout.closed


class TestClock:
    def test_converts_ktime_to_wall(self):
        c = Clock(wall_ns=1_000_000_000_000, mono_ns=500)
        assert c.to_wall_ns(1500) == 1_000_000_001_000

    def test_to_datetime_is_utc(self):
        dt = CLOCK.to_datetime(1_000_000_000)
        assert dt.tzinfo is not None
        assert dt.utcoffset().total_seconds() == 0

    def test_now_is_constructible(self):
        c = Clock.now()
        assert c.to_wall_ns(0) != 0


def test_formatters_satisfy_protocol():
    for f in (TextFormatter(CLOCK), JsonlFormatter(CLOCK)):
        assert isinstance(f.format(make_event()), str)


@pytest.mark.parametrize("verdict", list(Verdict))
def test_all_verdicts_render_in_both_formats(verdict):
    e = make_event(verdict=int(verdict))
    assert verdict.label in TextFormatter(CLOCK).format(e)
    assert json.loads(JsonlFormatter(CLOCK).format(e))["verdict"] == verdict.label
