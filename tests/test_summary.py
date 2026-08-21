"""集計とパーセンタイル。"""

import socket

import pytest

from blockingio.event import Verdict
from blockingio.summary import (
    RESERVOIR_CAPACITY,
    Aggregator,
    percentile,
)
from tests.factories import ipv4_raw, make_event


class TestPercentile:
    def test_empty_is_none(self):
        assert percentile([], 0.5) is None

    def test_single_sample(self):
        assert percentile([42], 0.99) == 42

    def test_nearest_rank_returns_observed_value(self):
        # 補間しないので必ず実在する値が返る。
        s = list(range(1, 101))  # 1..100
        assert percentile(s, 0.50) == 50
        assert percentile(s, 0.95) == 95
        assert percentile(s, 0.99) == 99

    def test_two_samples(self):
        assert percentile([10, 20], 0.5) == 10
        assert percentile([10, 20], 1.0) == 20

    def test_p100_is_max(self):
        assert percentile([1, 5, 9], 1.0) == 9

    def test_result_is_always_a_member(self):
        s = [3, 7, 11, 19]
        for q in (0.1, 0.5, 0.9, 0.99, 1.0):
            assert percentile(s, q) in s


class TestAggregatorBasics:
    def test_rejects_unknown_group_by(self):
        with pytest.raises(ValueError):
            Aggregator(group_by="nope")

    def test_group_key_is_comm_pid_op_peer(self):
        agg = Aggregator(group_by="peer", seed=0)
        agg.add(make_event())
        agg.add(make_event())
        assert len(agg.rows()) == 1
        assert agg.rows()[0].count == 2

    def test_different_peer_makes_new_bucket(self):
        agg = Aggregator(group_by="peer", seed=0)
        agg.add(make_event())
        agg.add(make_event(raddr4=ipv4_raw("10.0.9.9")))
        assert len(agg.rows()) == 2

    def test_group_by_op_collapses_peers(self):
        agg = Aggregator(group_by="op", seed=0)
        agg.add(make_event())
        agg.add(make_event(raddr4=ipv4_raw("10.0.9.9")))
        assert len(agg.rows()) == 1

    def test_group_by_pid_collapses_ops(self):
        agg = Aggregator(group_by="pid", seed=0)
        agg.add(make_event(op=0))
        agg.add(make_event(op=1))
        assert len(agg.rows()) == 1

    def test_count_total_and_max(self):
        agg = Aggregator(seed=0)
        agg.add(make_event(duration_ns=100))
        agg.add(make_event(duration_ns=300))
        row = agg.rows()[0]
        assert row.count == 2
        assert row.total_ns == 400
        assert row.max_ns == 300

    def test_blocking_and_stall_counts(self):
        agg = Aggregator(seed=0)
        agg.add(make_event(verdict=int(Verdict.OK)))
        agg.add(make_event(verdict=int(Verdict.WARN)))
        agg.add(make_event(verdict=int(Verdict.STALL)))
        agg.add(make_event(verdict=int(Verdict.IDLE)))
        row = agg.rows()[0]
        assert row.count == 4
        assert row.blocking_count == 2  # WARN + STALL
        assert row.stall_count == 1
        assert agg.total_events == 4
        assert agg.total_blocking == 2
        assert agg.total_stalls == 1


class TestSorting:
    def test_rows_sorted_by_total_desc(self):
        # 「まず何を直すべきか」に答えるのがサマリの目的。
        agg = Aggregator(seed=0)
        agg.add(make_event(raddr4=ipv4_raw("10.0.0.1"), duration_ns=100))
        agg.add(make_event(raddr4=ipv4_raw("10.0.0.2"), duration_ns=5000))
        agg.add(make_event(raddr4=ipv4_raw("10.0.0.3"), duration_ns=1000))
        totals = [r.total_ns for r in agg.rows()]
        assert totals == sorted(totals, reverse=True)

    def test_top_n_truncates(self):
        agg = Aggregator(seed=0)
        for i in range(1, 11):
            agg.add(make_event(raddr4=ipv4_raw(f"10.0.0.{i}")))
        assert len(agg.rows(top=3)) == 3
        assert len(agg.rows()) == 10


class TestReservoir:
    def test_exact_percentiles_below_capacity(self):
        agg = Aggregator(seed=0)
        for i in range(1, 101):
            agg.add(make_event(duration_ns=i))
        row = agg.rows()[0]
        assert row.p50 == 50
        assert row.p95 == 95
        assert row.p99 == 99

    def test_bounded_above_capacity(self):
        agg = Aggregator(seed=42)
        n = RESERVOIR_CAPACITY * 3
        for i in range(n):
            agg.add(make_event(duration_ns=i + 1))
        row = agg.rows()[0]
        # 件数は正確、サンプルは有界。
        assert row.count == n
        assert row.total_ns == sum(range(1, n + 1))
        assert row.max_ns == n

    def test_deterministic_with_seed(self):
        def run():
            agg = Aggregator(seed=7)
            for i in range(RESERVOIR_CAPACITY * 2):
                agg.add(make_event(duration_ns=i + 1))
            return agg.rows()[0]

        a, b = run(), run()
        assert (a.p50, a.p95, a.p99) == (b.p50, b.p95, b.p99)

    def test_percentiles_none_when_no_events(self):
        agg = Aggregator(seed=0)
        assert agg.rows() == []


class TestRender:
    def test_empty_render_mentions_no_events(self):
        out = Aggregator(seed=0).render()
        assert "no events matched" in out

    def test_render_includes_header_and_rows(self):
        agg = Aggregator(seed=0)
        agg.add(make_event(duration_ns=1_500_000, verdict=int(Verdict.STALL)))
        out = agg.render(elapsed_s=30.0)
        assert "=== summary" in out
        assert "1 events" in out
        assert "30.0s" in out
        assert "10.0.3.14:5432" in out
        assert "peer" in out

    def test_render_is_multiline_table(self):
        agg = Aggregator(seed=0)
        agg.add(make_event(raddr4=ipv4_raw("10.0.0.1")))
        agg.add(make_event(raddr4=ipv4_raw("10.0.0.2")))
        lines = agg.render().splitlines()
        assert len(lines) == 4  # head + header + 2 rows

    def test_row_as_dict_has_group_fields(self):
        agg = Aggregator(group_by="peer", seed=0)
        agg.add(make_event())
        d = agg.rows()[0].as_dict()
        for key in ("comm", "pid", "op", "peer", "count", "total_ms", "p99_ms"):
            assert key in d


def test_netlink_and_dash_peers_group_separately():
    agg = Aggregator(seed=0)
    agg.add(make_event(family=0))
    agg.add(make_event(family=socket.AF_INET))
    assert len(agg.rows()) == 2
