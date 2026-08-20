"""runtime の純粋部分。bcc に触る関数は呼ばないので macOS でも動く。"""

import platform

import pytest

from blockingio import runtime


class TestParseKernelVersion:
    @pytest.mark.parametrize(
        "release,expected",
        [
            ("5.15.0", (5, 15)),
            ("5.15.0-91-generic", (5, 15)),
            ("6.8.0-45-generic", (6, 8)),
            ("6", (6, 0)),
            ("4.9", (4, 9)),
            ("6.1.0-rc1", (6, 1)),
        ],
    )
    def test_parses(self, release, expected):
        assert runtime.parse_kernel_version(release) == expected

    @pytest.mark.parametrize("release", ["unknown", "", "a.b", "x"])
    def test_garbage_returns_none(self, release):
        assert runtime.parse_kernel_version(release) is None


class TestCheckEnvironment:
    def test_raises_on_non_linux(self, monkeypatch):
        monkeypatch.setattr(platform, "system", lambda: "Darwin")
        with pytest.raises(runtime.SetupError, match="only Linux"):
            runtime.check_environment()

    def test_raises_on_old_kernel(self, monkeypatch):
        monkeypatch.setattr(platform, "system", lambda: "Linux")
        monkeypatch.setattr(platform, "release", lambda: "4.4.0-generic")
        with pytest.raises(runtime.SetupError, match="too old"):
            runtime.check_environment()

    def test_raises_on_unparseable_release(self, monkeypatch):
        monkeypatch.setattr(platform, "system", lambda: "Linux")
        monkeypatch.setattr(platform, "release", lambda: "weird")
        with pytest.raises(runtime.SetupError, match="unknown kernel"):
            runtime.check_environment()

    def test_passes_on_new_kernel(self, monkeypatch):
        monkeypatch.setattr(platform, "system", lambda: "Linux")
        monkeypatch.setattr(platform, "release", lambda: "6.8.0-45-generic")
        runtime.check_environment()

    def test_accepts_exact_minimum(self, monkeypatch):
        monkeypatch.setattr(platform, "system", lambda: "Linux")
        monkeypatch.setattr(platform, "release", lambda: "4.9.0")
        runtime.check_environment()


class TestEscapeCString:
    def test_plain_name(self):
        assert runtime.escape_c_string("python3") == "python3"

    def test_escapes_quote(self):
        # 生の値を埋めると C ソース injection ができてしまう。
        assert runtime.escape_c_string('a"b') == 'a\\"b'

    def test_escapes_backslash(self):
        assert runtime.escape_c_string("a\\b") == "a\\\\b"

    def test_rejects_non_ascii(self):
        with pytest.raises(runtime.SetupError):
            runtime.escape_c_string("日本語")


class TestSubstitute:
    SRC = (
        "#if {USE_PID_FILTER}\n{TARGET_PID}\n#else\n"
        '"{TARGET_COMM}"\n#endif\n{MIN_LATENCY_NS} {STALL_LATENCY_NS} '
        "{TRACE_FILE_IO} {TRACE_WAIT} {REQUIRE_LOOP_THREAD}"
    )

    def call(self, **kw):
        base = {
            "pid": None,
            "process_name": "python3",
            "min_latency_ns": 1_000_000,
            "stall_latency_ns": 50_000_000,
            "trace_file_io": False,
            "trace_wait": True,
            "all_threads": False,
        }
        base.update(kw)
        return runtime.substitute(self.SRC, **base)

    def test_pid_mode_sets_filter_flag(self):
        out = self.call(pid=1234)
        assert "#if 1" in out
        assert "1234" in out

    def test_comm_mode_clears_filter_flag(self):
        out = self.call(pid=None)
        assert "#if 0" in out
        assert '"python3"' in out

    def test_pid_zero_is_honored(self):
        # 旧実装は `if args.pid:` だったので --pid 0 が無視されていた。
        out = self.call(pid=0)
        assert "#if 1" in out

    def test_no_placeholder_survives_in_pid_mode(self):
        out = self.call(pid=1234)
        assert "{" not in out

    def test_no_placeholder_survives_in_comm_mode(self):
        out = self.call(pid=None)
        assert "{" not in out

    def test_rejects_comm_over_15_bytes(self):
        # カーネルが comm を切り詰めるので、長い名前は永久にマッチしない。
        with pytest.raises(runtime.SetupError, match="longer than"):
            self.call(process_name="a" * 16)

    def test_accepts_comm_at_15_bytes(self):
        self.call(process_name="a" * 15)

    def test_escapes_quotes_in_comm(self):
        out = self.call(process_name='a"; }')
        assert '\\"' in out

    def test_min_latency_is_substituted(self):
        assert "2500000" in self.call(min_latency_ns=2_500_000)

    def test_stall_latency_is_independent_of_min_latency(self):
        # 同一の値にすると --min-latency 0 が「全表示」と「全て STALL」を
        # 同時に意味してしまうので、独立していることを固定する。
        out = self.call(min_latency_ns=0, stall_latency_ns=50_000_000)
        assert "0 50000000" in out

    def test_file_io_gate(self):
        assert self.call(trace_file_io=True).endswith("1 1 1")
        assert self.call(trace_file_io=False).endswith("0 1 1")

    def test_all_threads_inverts_loop_thread_gate(self):
        assert self.call(all_threads=True).endswith("0")
        assert self.call(all_threads=False).endswith("1")


class TestParseFdinfoFlags:
    def test_parses_octal(self):
        assert runtime.parse_fdinfo_flags("pos:\t0\nflags:\t02004002\n") == 0o2004002

    def test_detects_nonblock(self):
        flags = runtime.parse_fdinfo_flags("flags:\t04002\n")
        assert flags is not None
        assert flags & runtime.O_NONBLOCK

    def test_detects_blocking(self):
        flags = runtime.parse_fdinfo_flags("flags:\t02\n")
        assert flags is not None
        assert not flags & runtime.O_NONBLOCK

    def test_missing_field_is_none(self):
        assert runtime.parse_fdinfo_flags("pos:\t0\nmnt_id:\t9\n") is None

    def test_garbage_value_is_none(self):
        assert runtime.parse_fdinfo_flags("flags:\tnope\n") is None

    def test_empty_is_none(self):
        assert runtime.parse_fdinfo_flags("") is None


class TestScanPidFds:
    def test_reads_nonblock_states(self):
        files = {
            "/proc/42/fdinfo/3": "flags:\t04002\n",
            "/proc/42/fdinfo/4": "flags:\t02\n",
        }
        out = runtime.scan_pid_fds(
            42,
            read_file=files.get,
            listdir=lambda p: ["3", "4"],
        )
        assert out == {3: True, 4: False}

    def test_skips_non_numeric_entries(self):
        out = runtime.scan_pid_fds(
            42,
            read_file=lambda p: "flags:\t04002\n",
            listdir=lambda p: ["3", "notanfd"],
        )
        assert out == {3: True}

    def test_tolerates_closed_fd_race(self):
        out = runtime.scan_pid_fds(
            42,
            read_file=lambda p: None,
            listdir=lambda p: ["3"],
        )
        assert out == {}

    def test_missing_proc_dir_returns_empty(self):
        def boom(p):
            raise OSError("no such process")

        assert runtime.scan_pid_fds(42, read_file=lambda p: None, listdir=boom) == {}


class FakeTable:
    """BPF テーブルの代役。ctypes 構造体はハッシュ不能なので dict は使えない。"""

    def __init__(self):
        self.writes = []

    def __setitem__(self, key, value):
        self.writes.append(((key.pid, key.fd), value.value))


class TestSeedFdNonblock:
    def test_writes_into_table(self):
        table = FakeTable()
        n = runtime.seed_fd_nonblock(table, 42, {3: True, 4: False})
        assert n == 2
        assert dict(table.writes) == {(42, 3): 1, (42, 4): 0}

    def test_empty_state_writes_nothing(self):
        table = FakeTable()
        assert runtime.seed_fd_nonblock(table, 42, {}) == 0
        assert table.writes == []

    def test_key_struct_layout(self):
        import ctypes as ct

        # C 側 struct key_t {u32 pid; int fd;} と一致すること。
        assert ct.sizeof(runtime.KeyT) == 8
        assert [f[0] for f in runtime.KeyT._fields_] == ["pid", "fd"]


class TestPidsForComm:
    def test_matches_exact_name(self, monkeypatch):
        monkeypatch.setattr(runtime.glob, "glob", lambda p: ["/proc/10/comm", "/proc/20/comm"])
        files = {"/proc/10/comm": "python3\n", "/proc/20/comm": "bash\n"}
        assert runtime.pids_for_comm("python3", read_file=files.get) == [10]

    def test_matches_truncated_name(self, monkeypatch):
        # カーネルは comm を 15 バイトに切り詰めるので、こちらも切って比較する。
        monkeypatch.setattr(runtime.glob, "glob", lambda p: ["/proc/10/comm"])
        files = {"/proc/10/comm": "a" * 15 + "\n"}
        assert runtime.pids_for_comm("a" * 20, read_file=files.get) == [10]


class TestFindLibc:
    def test_uses_platform_machine(self, monkeypatch):
        monkeypatch.setattr(platform, "machine", lambda: "aarch64")
        seen = []

        def exists(p):
            seen.append(p)
            return p == "/lib/aarch64-linux-gnu/libc.so.6"

        monkeypatch.setattr(runtime.os.path, "exists", exists)
        assert runtime.find_libc() == "/lib/aarch64-linux-gnu/libc.so.6"

    def test_falls_back_to_musl(self, monkeypatch):
        monkeypatch.setattr(platform, "machine", lambda: "x86_64")
        monkeypatch.setattr(runtime.os.path, "exists", lambda p: p.startswith("/lib/ld-musl"))
        monkeypatch.setattr(runtime.glob, "glob", lambda p: ["/lib/ld-musl-x86_64.so.1"])
        assert runtime.find_libc() == "/lib/ld-musl-x86_64.so.1"


class TestImportBpf:
    def test_missing_bcc_gives_actionable_message(self, monkeypatch):
        import builtins

        real_import = builtins.__import__

        def fake_import(name, *a, **kw):
            if name == "bcc":
                raise ImportError("no bcc")
            return real_import(name, *a, **kw)

        monkeypatch.setattr(builtins, "__import__", fake_import)
        with pytest.raises(runtime.SetupError) as ei:
            runtime.import_bpf()
        msg = str(ei.value)
        assert "python3-bpfcc" in msg
        assert "unrelated project" in msg


def test_bpf_source_path_resolves_to_existing_file():
    # cwd に依存しないこと（旧実装は相対パスでリポジトリルート限定だった）。
    import os

    assert os.path.isfile(runtime.bpf_source_path())
