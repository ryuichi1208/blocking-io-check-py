"""表示可否の述語。

「表示すべきか」と「どう描くか」を分離しているので、両方が単体テストできる。
"""

from __future__ import annotations

from dataclasses import dataclass

from .event import AF_NETLINK, Event, Verdict

DNS_PORT = 53


@dataclass(frozen=True, slots=True)
class DisplayFilter:
    hide_dns: bool = False
    hide_netlink: bool = False
    min_duration_ns: int = 0
    ops: frozenset[str] | None = None
    min_verdict: Verdict | None = None

    def allows(self, e: Event) -> bool:
        # ポートで判定するので IPv4/IPv6 の両方で効く。
        if self.hide_dns and e.peer_port == DNS_PORT:
            return False
        if self.hide_netlink and e.family == AF_NETLINK:
            return False
        if e.duration_ns < self.min_duration_ns:
            return False
        if self.min_verdict is not None and e.verdict < self.min_verdict:
            return False
        return not (self.ops is not None and e.op not in self.ops)
