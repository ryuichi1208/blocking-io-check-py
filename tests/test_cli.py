"""argparse とハンドラの配線。bcc を必要としない範囲。"""

import ctypes as ct
import platform

import pytest

from blockingio import cli, runtime
from blockingio.event import IoEvt, Verdict
from blockingio.filters import DisplayFilter
from blockingio.summary import Aggregator
from tests.factories import make_raw


def parse(*argv):
    return cli.build_parser().parse_args(list(argv))


class TestDefaults:
    def test_process_name_default(self):
        assert parse().process_name == "python3"

    def test_pid_default_is_none(self):
        assert parse().pid is None

    def test_min_latency_default_is_1ms(self):
        # 既定で「問題のある I/O のみ」を出す。
        assert parse().min_latency == cli.DEFAULT_MIN_LATENCY_MS

    def test_wait_tracing_on_by_default(self):
        assert parse().include_wait is True

    def test_file_io_off_by_default(self):
        assert parse().file_io is False

    def test_json_off_by_default(self):
        assert parse().json is False

    def test_duration_default_is_none(self):
        assert parse().duration is None

    def test_top_default(self):
        assert parse().top == 20

    def test_group_by_default(self):
        assert parse().group_by == "peer"

    def test_fail_on_blocking_off_by_default(self):
        # 既定で非ゼロ終了しないこと。対話利用を壊さないため。
        assert parse().fail_on_blocking is False


class TestFlags:
    def test_pid_zero_is_parsed_as_zero(self):
        # 旧実装の `if args.pid:` は --pid 0 を落としていた。
        assert parse("--pid", "0").pid == 0

    def test_pid_zero_selects_pid_mode(self):
        args = parse("--pid", "0")
        assert args.pid is not None

    def test_min_latency_zero_allowed(self):
        assert parse("--min-latency", "0").min_latency == 0.0

    def test_no_include_wait(self):
        assert parse("--no-include-wait").include_wait is False

    def test_duration_accepts_float(self):
        assert parse("-d", "1.5").duration == 1.5

    def test_output_file(self):
        assert parse("-o", "/tmp/x.jsonl").output == "/tmp/x.jsonl"

    def test_json_and_no_color_compatible(self):
        args = parse("--json", "--no-color")
        assert args.json and args.no_color

    def test_duration_and_summary_only_compatible(self):
        args = parse("-d", "10", "--summary-only")
        assert args.duration == 10 and args.summary_only

    def test_group_by_rejects_unknown(self):
        with pytest.raises(SystemExit):
            parse("--group-by", "nope")

    def test_version_exits_zero(self, capsys):
        with pytest.raises(SystemExit) as ei:
            parse("--version")
        assert ei.value.code == 0
        assert "0.2.0" in capsys.readouterr().out


class TestResolveOps:
    def test_none_when_unset(self):
        assert cli.resolve_ops(None) is None
        assert cli.resolve_ops("") is None

    def test_parses_list(self):
        assert cli.resolve_ops("read,recvfrom") == frozenset({"read", "recvfrom"})

    def test_tolerates_whitespace(self):
        assert cli.resolve_ops(" read , write ") == frozenset({"read", "write"})

    def test_rejects_unknown_op(self):
        with pytest.raises(runtime.SetupError, match="unknown op"):
            cli.resolve_ops("read,nope")


class TestHandler:
    def emit(self, raw, flt=None, agg=None):
        """perf buffer と等価にポインタ経由で呼ぶ。"""
        seen = []

        class Sink:
            def emit(self, e):
                seen.append(e)

        handler = cli.make_handler(Sink(), flt or DisplayFilter(), agg)
        handler(0, ct.addressof(raw), ct.sizeof(raw))
        return seen

    def test_decodes_raw_pointer(self):
        seen = self.emit(make_raw(pid=1234, fd=7, op=5))
        assert len(seen) == 1
        assert seen[0].pid == 1234
        assert seen[0].fd == 7
        assert seen[0].op == "read"

    def test_respects_filter(self):
        raw = make_raw(duration_ns=100)
        assert self.emit(raw, flt=DisplayFilter(min_duration_ns=1000)) == []

    def test_feeds_aggregator(self):
        agg = Aggregator(seed=0)
        self.emit(make_raw(), agg=agg)
        assert agg.total_events == 1

    def test_filtered_event_not_aggregated(self):
        agg = Aggregator(seed=0)
        self.emit(make_raw(duration_ns=100), flt=DisplayFilter(min_duration_ns=1000), agg=agg)
        assert agg.total_events == 0

    def test_works_without_sink(self):
        agg = Aggregator(seed=0)
        handler = cli.make_handler(None, DisplayFilter(), agg)
        raw = make_raw()
        handler(0, ct.addressof(raw), ct.sizeof(raw))
        assert agg.total_events == 1

    def test_struct_size_is_stable(self):
        # レイアウトが変わったら気づけるように固定しておく。
        assert ct.sizeof(IoEvt) == 96


class TestExitCode:
    def agg_with(self, verdict):
        from blockingio.event import Event

        agg = Aggregator(seed=0)
        agg.add(Event.from_ctypes(make_raw(verdict=int(verdict))))
        return agg

    def test_no_aggregator_is_ok(self):
        assert cli.exit_code(None, fail_on_blocking=True) == cli.EXIT_OK

    def test_stall_without_flag_is_ok(self):
        # 既定では検出しても 0。対話利用や && の連鎖を壊さないため。
        agg = self.agg_with(Verdict.STALL)
        assert cli.exit_code(agg, fail_on_blocking=False) == cli.EXIT_OK

    def test_stall_with_flag_is_blocking_code(self):
        agg = self.agg_with(Verdict.STALL)
        assert cli.exit_code(agg, fail_on_blocking=True) == cli.EXIT_BLOCKING

    def test_warn_with_flag_is_blocking_code(self):
        agg = self.agg_with(Verdict.WARN)
        assert cli.exit_code(agg, fail_on_blocking=True) == cli.EXIT_BLOCKING

    @pytest.mark.parametrize("verdict", [Verdict.OK, Verdict.IDLE])
    def test_clean_verdicts_do_not_trip_the_gate(self, verdict):
        # 長い epoll_wait でゲートが落ちてはならない。
        agg = self.agg_with(verdict)
        assert cli.exit_code(agg, fail_on_blocking=True) == cli.EXIT_OK

    def test_empty_aggregator_is_ok(self):
        assert cli.exit_code(Aggregator(seed=0), fail_on_blocking=True) == cli.EXIT_OK


class TestSetupFailures:
    def test_non_linux_exits_setup_code(self, monkeypatch, capsys):
        monkeypatch.setattr(platform, "system", lambda: "Darwin")
        assert cli.main([]) == cli.EXIT_SETUP
        assert "only Linux" in capsys.readouterr().err

    def test_old_kernel_exits_setup_code(self, monkeypatch, capsys):
        monkeypatch.setattr(platform, "system", lambda: "Linux")
        monkeypatch.setattr(platform, "release", lambda: "3.10.0")
        assert cli.main([]) == cli.EXIT_SETUP
        assert "too old" in capsys.readouterr().err

    def test_bad_op_exits_setup_code(self, monkeypatch, capsys):
        monkeypatch.setattr(platform, "system", lambda: "Darwin")
        assert cli.main(["--op", "bogus"]) == cli.EXIT_SETUP
        assert "unknown op" in capsys.readouterr().err

    def test_long_process_name_exits_setup_code(self, monkeypatch, capsys):
        # substitute の検証まで到達しないので check_environment を通す必要がある。
        monkeypatch.setattr(platform, "system", lambda: "Darwin")
        assert cli.main(["-p", "a" * 20]) == cli.EXIT_SETUP


def test_exit_codes_are_distinct():
    # CI が「ツールが壊れた」と「ツールが何か見つけた」を区別できること。
    assert len({cli.EXIT_OK, cli.EXIT_SETUP, cli.EXIT_BLOCKING}) == 3
    assert cli.EXIT_OK == 0


def test_shim_imports_same_main():
    import blocking_io_check

    assert blocking_io_check.main is cli.main


def test_parser_help_mentions_all_verdicts():
    # verdict の意味は README に書くが、少なくとも列挙は壊れていないこと。
    assert [v.label for v in Verdict] == ["OK", "IDLE", "WARN", "STALL"]
