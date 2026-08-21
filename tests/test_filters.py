"""表示述語。"""

import socket

from blockingio.event import AF_NETLINK, Verdict
from blockingio.filters import DisplayFilter
from tests.factories import make_event


def dns_v4():
    return make_event(rport=socket.htons(53))


def dns_v6():
    return make_event(family=socket.AF_INET6, addr6="::1", rport=socket.htons(53))


class TestHideDns:
    def test_hides_ipv4_port_53(self):
        assert DisplayFilter(hide_dns=True).allows(dns_v4()) is False

    def test_hides_ipv6_port_53(self):
        # 旧実装は AF_INET ブランチ内でしか判定していなかったので IPv6 が漏れていた。
        assert DisplayFilter(hide_dns=True).allows(dns_v6()) is False

    def test_keeps_other_ports(self):
        assert DisplayFilter(hide_dns=True).allows(make_event()) is True

    def test_disabled_keeps_dns(self):
        assert DisplayFilter(hide_dns=False).allows(dns_v4()) is True


class TestHideNetlink:
    def test_hides_netlink(self):
        e = make_event(family=AF_NETLINK)
        assert DisplayFilter(hide_netlink=True).allows(e) is False

    def test_disabled_keeps_netlink(self):
        e = make_event(family=AF_NETLINK)
        assert DisplayFilter(hide_netlink=False).allows(e) is True


class TestMinDuration:
    def test_filters_below_threshold(self):
        e = make_event(duration_ns=500)
        assert DisplayFilter(min_duration_ns=1000).allows(e) is False

    def test_keeps_at_threshold(self):
        e = make_event(duration_ns=1000)
        assert DisplayFilter(min_duration_ns=1000).allows(e) is True


class TestOpAllowlist:
    def test_allows_listed_op(self):
        e = make_event(op=1)  # recvfrom
        assert DisplayFilter(ops=frozenset({"recvfrom"})).allows(e) is True

    def test_rejects_unlisted_op(self):
        e = make_event(op=1)
        assert DisplayFilter(ops=frozenset({"sendto"})).allows(e) is False


class TestMinVerdict:
    def test_only_blocking_rejects_ok(self):
        e = make_event(verdict=int(Verdict.OK))
        assert DisplayFilter(min_verdict=Verdict.WARN).allows(e) is False

    def test_only_blocking_rejects_idle(self):
        e = make_event(verdict=int(Verdict.IDLE))
        assert DisplayFilter(min_verdict=Verdict.WARN).allows(e) is False

    def test_only_blocking_accepts_warn_and_stall(self):
        f = DisplayFilter(min_verdict=Verdict.WARN)
        assert f.allows(make_event(verdict=int(Verdict.WARN))) is True
        assert f.allows(make_event(verdict=int(Verdict.STALL))) is True


def test_default_filter_allows_everything():
    assert DisplayFilter().allows(make_event()) is True
    assert DisplayFilter().allows(dns_v4()) is True
    assert DisplayFilter().allows(make_event(family=AF_NETLINK)) is True
