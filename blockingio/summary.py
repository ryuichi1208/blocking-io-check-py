"""集計とパーセンタイル。

「まず何を直すべきか」に答えるのがサマリの存在意義なので、合計ブロック時間の
降順でソートする。
"""

from __future__ import annotations

import random
from collections import Counter
from dataclasses import dataclass, field

from .event import Event, Verdict

# バケットあたりのサンプル上限。
#
# 固定サイズのリザーバサンプリング (Algorithm R) を使う。2048 未満なら厳密な
# リストなので p50/p95/p99 が正確で、これが圧倒的多数のケース。超えても
# 2048 x 8 バイト = 16KB/バケットで有界。
#
# 無制限リストは長時間実行で OOM、HDR ヒストグラムは境界補間と専用テストが
# 必要になり、助言的な percentile に対して過剰。この判断は再検討しないこと。
RESERVOIR_CAPACITY = 2048

GROUP_FIELDS = {
    "peer": ("comm", "pid", "op", "peer"),
    "op": ("comm", "op"),
    "pid": ("comm", "pid"),
    "fd": ("comm", "pid", "fd", "op"),
}


def _ms(n: int | None) -> str:
    return "-" if n is None else f"{n / 1e6:.3f}"


def percentile(sorted_samples: list[int], q: float) -> int | None:
    """nearest-rank 方式。実際に観測された値を返すのでログで引ける。

    線形補間は使わない（存在しない値を返してしまう）。
    """
    n = len(sorted_samples)
    if n == 0:
        return None
    if n == 1:
        return sorted_samples[0]
    import math

    rank = max(1, math.ceil(q * n))
    return sorted_samples[min(n, rank) - 1]


@dataclass
class Bucket:
    count: int = 0
    blocking_count: int = 0
    stall_count: int = 0
    total_ns: int = 0
    max_ns: int = 0
    samples: list[int] = field(default_factory=list)
    verdicts: Counter[str] = field(default_factory=Counter)

    def add(self, e: Event, rng: random.Random) -> None:
        self.count += 1
        self.total_ns += e.duration_ns
        self.max_ns = max(self.max_ns, e.duration_ns)
        self.verdicts[e.verdict.label] += 1
        if e.is_blocking:
            self.blocking_count += 1
        if e.verdict is Verdict.STALL:
            self.stall_count += 1

        if len(self.samples) < RESERVOIR_CAPACITY:
            self.samples.append(e.duration_ns)
        else:
            # Algorithm R: i 番目の要素を capacity/i の確率で採用する。
            j = rng.randrange(self.count)
            if j < RESERVOIR_CAPACITY:
                self.samples[j] = e.duration_ns

    def percentiles(self) -> dict[str, int | None]:
        s = sorted(self.samples)
        return {
            "p50": percentile(s, 0.50),
            "p95": percentile(s, 0.95),
            "p99": percentile(s, 0.99),
        }


@dataclass(frozen=True, slots=True)
class SummaryRow:
    key: tuple[object, ...]
    fields: tuple[str, ...]
    count: int
    blocking_count: int
    stall_count: int
    total_ns: int
    max_ns: int
    p50: int | None
    p95: int | None
    p99: int | None

    def as_dict(self) -> dict[str, object]:
        d: dict[str, object] = dict(zip(self.fields, self.key, strict=True))
        d.update(
            count=self.count,
            blocking=self.blocking_count,
            stalls=self.stall_count,
            total_ms=round(self.total_ns / 1e6, 3),
            max_ms=round(self.max_ns / 1e6, 3),
            p50_ms=None if self.p50 is None else round(self.p50 / 1e6, 3),
            p95_ms=None if self.p95 is None else round(self.p95 / 1e6, 3),
            p99_ms=None if self.p99 is None else round(self.p99 / 1e6, 3),
        )
        return d


class Aggregator:
    def __init__(self, group_by: str = "peer", seed: int | None = None) -> None:
        if group_by not in GROUP_FIELDS:
            raise ValueError(f"unknown group_by: {group_by}")
        self._fields = GROUP_FIELDS[group_by]
        self._buckets: dict[tuple[object, ...], Bucket] = {}
        self._rng = random.Random(seed)
        self.total_events = 0
        self.total_blocking = 0
        self.total_stalls = 0

    def add(self, e: Event) -> None:
        self.total_events += 1
        if e.is_blocking:
            self.total_blocking += 1
        if e.verdict is Verdict.STALL:
            self.total_stalls += 1
        key = tuple(getattr(e, f) for f in self._fields)
        bucket = self._buckets.get(key)
        if bucket is None:
            bucket = self._buckets[key] = Bucket()
        bucket.add(e, self._rng)

    def rows(self, top: int | None = None) -> list[SummaryRow]:
        rows = []
        for key, b in self._buckets.items():
            p = b.percentiles()
            rows.append(
                SummaryRow(
                    key=key,
                    fields=self._fields,
                    count=b.count,
                    blocking_count=b.blocking_count,
                    stall_count=b.stall_count,
                    total_ns=b.total_ns,
                    max_ns=b.max_ns,
                    p50=p["p50"],
                    p95=p["p95"],
                    p99=p["p99"],
                )
            )
        rows.sort(key=lambda r: r.total_ns, reverse=True)
        if top is not None:
            rows = rows[:top]
        return rows

    def render(self, top: int | None = 20, elapsed_s: float | None = None) -> str:
        rows = self.rows(top)
        head = (
            f"=== summary ({self.total_events} events, "
            f"{self.total_blocking} blocking, {self.total_stalls} stalls"
        )
        if elapsed_s is not None:
            head += f", {elapsed_s:.1f}s"
        head += ") ==="
        if not rows:
            return head + "\n(no events matched)"

        labels = {
            "comm": "comm",
            "pid": "pid",
            "op": "op",
            "peer": "peer",
            "fd": "fd",
        }
        widths = {f: len(labels[f]) for f in self._fields}
        for r in rows:
            for f, v in zip(self._fields, r.key, strict=True):
                widths[f] = max(widths[f], len(str(v)))

        header = "  ".join(f"{labels[f]:<{widths[f]}}" for f in self._fields)
        header += "  count  block  stall     total       max       p50       p95       p99"
        lines = [head, header]
        for r in rows:
            line = "  ".join(
                f"{v!s:<{widths[f]}}" for f, v in zip(self._fields, r.key, strict=True)
            )
            line += (
                f"  {r.count:>5}  {r.blocking_count:>5}  {r.stall_count:>5}"
                f"  {r.total_ns / 1e6:>8.2f}  {r.max_ns / 1e6:>8.3f}"
                f"  {_ms(r.p50):>8}  {_ms(r.p95):>8}  {_ms(r.p99):>8}"
            )
            lines.append(line)
        return "\n".join(lines)
