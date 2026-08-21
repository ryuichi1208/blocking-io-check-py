"""classify() の真理値表。これがブロッキング判定の仕様。"""

import pytest

from blockingio.event import (
    NB_BLOCKING,
    NB_NONBLOCK,
    NB_UNKNOWN,
    Verdict,
    classify,
)

STALL_NS = 1_000_000  # 1ms
LONG = STALL_NS * 20  # 閾値の 20 倍 = 非ブロッキング fd でも WARN になる領域
OVER = STALL_NS * 2  # 閾値超えだが非ブロッキング fd なら OK の領域
UNDER = STALL_NS // 2


def call(**kw):
    base = {
        "nonblock": NB_BLOCKING,
        "via_epoll": False,
        "msg_dontwait": False,
        "duration_ns": UNDER,
        "op": "recvfrom",
        "stall_ns": STALL_NS,
        "on_loop_thread": True,
    }
    base.update(kw)
    return classify(**base)


class TestWaitOps:
    """待機系 syscall は長くても正常。イベントループがアイドルしているだけ。"""

    @pytest.mark.parametrize("op", ["epoll_wait", "poll", "select"])
    def test_wait_op_is_idle_even_when_very_long(self, op):
        assert call(op=op, duration_ns=LONG * 100) == Verdict.IDLE

    @pytest.mark.parametrize("op", ["epoll_wait", "poll", "select"])
    def test_wait_op_is_idle_even_on_blocking_fd(self, op):
        # 待機系は必ず IDLE。他のどのフラグにも影響されない。
        assert call(op=op, nonblock=NB_BLOCKING, via_epoll=False) == Verdict.IDLE


class TestShortCircuits:
    def test_dontwait_never_blocks(self):
        assert call(msg_dontwait=True, duration_ns=LONG) == Verdict.OK

    def test_unknown_state_never_stalls(self):
        # 最重要: 状態不明なら断定しない。誤検知の再発を防ぐ歯止め。
        assert call(nonblock=NB_UNKNOWN, duration_ns=LONG) == Verdict.OK


class TestNonblockingFd:
    def test_short_is_ok(self):
        assert call(nonblock=NB_NONBLOCK, duration_ns=UNDER) == Verdict.OK

    def test_over_threshold_but_not_extreme_is_ok(self):
        # 非ブロッキング fd が閾値を少し超えるのは正常範囲。
        assert call(nonblock=NB_NONBLOCK, duration_ns=OVER) == Verdict.OK

    def test_extremely_long_is_warn(self):
        # 非ブロッキングなのに極端に長い = カーネル/NIC 側の別要因。
        assert call(nonblock=NB_NONBLOCK, duration_ns=LONG) == Verdict.WARN


class TestBlockingFd:
    def test_under_threshold_is_ok(self):
        assert call(nonblock=NB_BLOCKING, duration_ns=UNDER) == Verdict.OK

    def test_over_threshold_is_stall(self):
        assert call(nonblock=NB_BLOCKING, duration_ns=OVER) == Verdict.STALL

    def test_exactly_at_threshold_is_stall(self):
        assert call(nonblock=NB_BLOCKING, duration_ns=STALL_NS) == Verdict.STALL

    def test_epoll_registered_is_warn_not_stall(self):
        # epoll 登録済みでブロッキングは矛盾。追跡漏れの可能性があるので断定しない。
        assert call(nonblock=NB_BLOCKING, via_epoll=True, duration_ns=LONG) == Verdict.WARN

    def test_off_loop_thread_is_ok(self):
        # run_in_executor のワーカでのブロッキング I/O はそのスレッドの仕事。
        assert call(nonblock=NB_BLOCKING, duration_ns=LONG, on_loop_thread=False) == Verdict.OK

    def test_on_loop_thread_is_stall(self):
        assert call(nonblock=NB_BLOCKING, duration_ns=LONG, on_loop_thread=True) == Verdict.STALL


class TestFileOps:
    def test_blocking_fsync_over_threshold_is_stall(self):
        # ファイル I/O も同じ規則。イベントループ上の遅い fsync はストール。
        assert call(op="fsync", nonblock=NB_BLOCKING, duration_ns=OVER) == Verdict.STALL


# nonblock x via_epoll x dontwait x duration の直積。仕様の全面固定。
@pytest.mark.parametrize(
    "nonblock,via_epoll,dontwait,duration,expected",
    [
        # 明示的に待たない指定は常に OK
        (NB_BLOCKING, False, True, LONG, Verdict.OK),
        (NB_NONBLOCK, False, True, LONG, Verdict.OK),
        (NB_UNKNOWN, False, True, LONG, Verdict.OK),
        # 不明は常に OK
        (NB_UNKNOWN, False, False, UNDER, Verdict.OK),
        (NB_UNKNOWN, True, False, LONG, Verdict.OK),
        # 非ブロッキング
        (NB_NONBLOCK, False, False, UNDER, Verdict.OK),
        (NB_NONBLOCK, True, False, OVER, Verdict.OK),
        (NB_NONBLOCK, True, False, LONG, Verdict.WARN),
        # ブロッキング
        (NB_BLOCKING, False, False, UNDER, Verdict.OK),
        (NB_BLOCKING, False, False, OVER, Verdict.STALL),
        (NB_BLOCKING, True, False, UNDER, Verdict.WARN),
        (NB_BLOCKING, True, False, LONG, Verdict.WARN),
    ],
)
def test_truth_table(nonblock, via_epoll, dontwait, duration, expected):
    assert (
        call(
            nonblock=nonblock,
            via_epoll=via_epoll,
            msg_dontwait=dontwait,
            duration_ns=duration,
        )
        == expected
    )
