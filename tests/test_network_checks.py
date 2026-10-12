"""Network check tests: ping argv/parsing, TCP fallback and DNS degradation.

No real network I/O happens here: ``run_command``, ``_tcp_latency`` and
``socket.gethostbyname`` are patched, so every test is deterministic and works
offline on any platform.
"""

from __future__ import annotations

import sys

import pytest

from lintest.checks import network
from lintest.config import Config, NetworkConfig
from lintest.models import Severity
from lintest.utils.shell import CommandResult

IPUTILS_OK = """PING 1.1.1.1 (1.1.1.1) 56(84) bytes of data.
64 bytes from 1.1.1.1: icmp_seq=1 ttl=57 time=8.11 ms
64 bytes from 1.1.1.1: icmp_seq=2 ttl=57 time=9.02 ms

--- 1.1.1.1 ping statistics ---
2 packets transmitted, 2 received, 0% packet loss, time 1001ms
rtt min/avg/max/mdev = 8.110/8.565/9.020/0.455 ms
"""

IPUTILS_SLOW = """PING 1.1.1.1 (1.1.1.1) 56(84) bytes of data.
64 bytes from 1.1.1.1: icmp_seq=1 ttl=57 time=612.5 ms

--- 1.1.1.1 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 612.500/612.500/612.500/0.000 ms
"""

IPUTILS_TOTAL_LOSS = """PING 1.1.1.1 (1.1.1.1) 56(84) bytes of data.

--- 1.1.1.1 ping statistics ---
3 packets transmitted, 0 received, 100% packet loss, time 2002ms
"""

BUSYBOX_OK = """PING 1.1.1.1 (1.1.1.1): 56 data bytes
64 bytes from 1.1.1.1: seq=0 ttl=57 time=12.500 ms

--- 1.1.1.1 ping statistics ---
1 packets transmitted, 1 packets received, 0% packet loss
round-trip min/avg/max = 12.500/12.500/12.500 ms
"""

#: What ``ping`` prints on a host whose implementation does not understand the
#: options we pass (this is exactly what Windows' ping.exe does with ``-c``).
UNUSABLE_PROBE = "Bad option -c.\n"

#: Real Windows ``ping.exe`` output, verbatim (reachable host).
WINDOWS_OK = """Pinging 1.1.1.1 with 32 bytes of data:
Reply from 1.1.1.1: bytes=32 time=12ms TTL=57
Reply from 1.1.1.1: bytes=32 time=11ms TTL=57

Ping statistics for 1.1.1.1:
    Packets: Sent = 2, Received = 2, Lost = 0 (0% loss),
Approximate round trip times in milli-seconds:
    Minimum = 11ms, Maximum = 12ms, Average = 11ms
"""

#: Real Windows ``ping.exe`` output, verbatim (unreachable host).
WINDOWS_TOTAL_LOSS = """Pinging 203.0.113.7 with 32 bytes of data:
Request timed out.
Request timed out.
Request timed out.

Ping statistics for 203.0.113.7:
    Packets: Sent = 3, Received = 0, Lost = 3 (100% loss),
"""


def ping_cfg(count: int = 2, timeout: float = 2.0, **kw) -> Config:
    return Config(network=NetworkConfig(
        ping_hosts=["1.1.1.1"], ping_count=count, ping_timeout_seconds=timeout,
        tcp_timeout_seconds=1.0, dns_host="google.com", **kw))


def fake_result(stdout: str = "", stderr: str = "", returncode: int = 0, **kw) -> CommandResult:
    return CommandResult(argv=["ping"], returncode=returncode, stdout=stdout,
                         stderr=stderr, **kw)


class TestPingArgv:
    @pytest.fixture(autouse=True)
    def _pin_linux(self, monkeypatch):
        """These assert the iputils variant; the Windows variant is pinned
        explicitly in :class:`TestPingArgvWindows` so neither can pass
        vacuously on the other platform."""
        monkeypatch.setattr(sys, "platform", "linux")

    def test_whole_second_options(self):
        argv = network._ping_argv(ping_cfg(count=2, timeout=2.0), "1.1.1.1")
        assert argv == ["ping", "-c", "2", "-W", "2", "-w", "4", "1.1.1.1"]

    def test_fractional_timeout_is_rounded_up_not_to_milliseconds(self):
        argv = network._ping_argv(ping_cfg(count=3, timeout=0.5), "host.example")
        assert argv[argv.index("-W") + 1] == "1"
        assert argv[argv.index("-w") + 1] == "2"
        assert all(part.isdigit() or part.startswith("-") or "." in part or part == "ping"
                   for part in argv)

    def test_deadline_never_zero(self):
        argv = network._ping_argv(ping_cfg(count=1, timeout=0.1), "h")
        assert argv[argv.index("-w") + 1] == "1"


class TestPingArgvWindows:
    """Windows ping.exe takes ``-n`` count and ``-w`` timeout in milliseconds."""

    @pytest.fixture(autouse=True)
    def _pin_windows(self, monkeypatch):
        monkeypatch.setattr(sys, "platform", "win32")

    def test_windows_uses_dash_n_and_millisecond_timeout(self):
        argv = network._ping_argv(ping_cfg(count=2, timeout=2.0), "1.1.1.1")
        assert argv == ["ping", "-n", "2", "-w", "2000", "1.1.1.1"]

    def test_windows_timeout_is_whole_milliseconds(self):
        argv = network._ping_argv(ping_cfg(count=3, timeout=0.5), "host.example")
        assert argv[argv.index("-w") + 1] == "500"
        assert "-c" not in argv and "-W" not in argv


class TestParsePingOutput:
    def test_iputils_summary(self):
        outcome = network._parse_ping_output("1.1.1.1", IPUTILS_OK, 2)
        assert outcome.parseable is True
        assert outcome.ok is True
        assert outcome.received == 2
        assert outcome.loss_percent == 0.0
        assert outcome.avg_ms == pytest.approx(8.565)

    def test_total_loss_is_parseable(self):
        outcome = network._parse_ping_output("1.1.1.1", IPUTILS_TOTAL_LOSS, 3)
        assert outcome.parseable is True
        assert outcome.ok is False
        assert outcome.loss_percent == 100.0
        assert outcome.received == 0

    def test_windows_summary(self):
        outcome = network._parse_ping_output("1.1.1.1", WINDOWS_OK, 2)
        assert outcome.parseable is True
        assert outcome.ok is True
        assert outcome.loss_percent == 0.0
        assert outcome.received == 2
        assert outcome.avg_ms == pytest.approx(11.0)

    def test_windows_total_loss_is_packet_loss_not_parse_failure(self):
        outcome = network._parse_ping_output("203.0.113.7", WINDOWS_TOTAL_LOSS, 3)
        assert outcome.parseable is True
        assert outcome.ok is False
        assert outcome.loss_percent == 100.0
        assert outcome.received == 0

    def test_busybox_reply_lines(self):
        outcome = network._parse_ping_output("1.1.1.1", BUSYBOX_OK, 1)
        assert outcome.parseable is True
        assert outcome.avg_ms == pytest.approx(12.5)
        assert outcome.received == 1

    def test_unparseable_output_is_flagged(self):
        outcome = network._parse_ping_output("1.1.1.1", UNUSABLE_PROBE, 2)
        assert outcome.parseable is False

    def test_empty_output_is_not_parseable(self):
        assert network._parse_ping_output("h", "", 2).parseable is False


class TestPingFallbacks:
    """A failure to *use* ICMP must never be reported as packet loss."""

    def test_unusable_probe_falls_back_to_tcp(self, monkeypatch):
        monkeypatch.setattr(network, "run_command",
                            lambda *a, **k: fake_result(stdout=UNUSABLE_PROBE, stderr="Bad option -c.", returncode=2))
        monkeypatch.setattr(network, "_tcp_latency", lambda *a, **k: 12.3)
        result = network._check_ping(ping_cfg(), "1.1.1.1")
        assert result.severity is Severity.INFO
        assert result.details["method"] == "tcp_fallback"
        assert "unusable" in result.message
        assert "packet loss" not in result.message

    def test_unusable_probe_and_dead_tcp_is_critical(self, monkeypatch):
        monkeypatch.setattr(network, "run_command",
                            lambda *a, **k: fake_result(stdout=UNUSABLE_PROBE, returncode=2))
        monkeypatch.setattr(network, "_tcp_latency", lambda *a, **k: None)
        result = network._check_ping(ping_cfg(), "1.1.1.1")
        assert result.severity is Severity.CRITICAL
        assert "unreachable" in result.message

    def test_missing_ping_binary_falls_back(self, monkeypatch):
        monkeypatch.setattr(network, "run_command",
                            lambda *a, **k: fake_result(missing=True, returncode=-1))
        monkeypatch.setattr(network, "_tcp_latency", lambda *a, **k: 4.0)
        result = network._check_ping(ping_cfg(), "1.1.1.1")
        assert result.severity is Severity.INFO
        assert "ping binary is unavailable" in result.message

    def test_missing_ping_binary_and_dead_tcp(self, monkeypatch):
        monkeypatch.setattr(network, "run_command",
                            lambda *a, **k: fake_result(missing=True, returncode=-1))
        monkeypatch.setattr(network, "_tcp_latency", lambda *a, **k: None)
        result = network._check_ping(ping_cfg(), "1.1.1.1")
        assert result.severity is Severity.CRITICAL

    def test_real_total_loss_stays_critical(self, monkeypatch):
        monkeypatch.setattr(network, "run_command",
                            lambda *a, **k: fake_result(stdout=IPUTILS_TOTAL_LOSS, returncode=1))
        monkeypatch.setattr(network, "_tcp_latency", lambda *a, **k: 5.0)
        result = network._check_ping(ping_cfg(), "1.1.1.1")
        assert result.severity is Severity.CRITICAL
        assert "100% packet loss" in result.message

    def test_windows_unreachable_is_packet_loss_critical(self, monkeypatch):
        """Real Windows output for a dead host must be packet loss, not a parse failure."""
        monkeypatch.setattr(network, "run_command",
                            lambda *a, **k: fake_result(stdout=WINDOWS_TOTAL_LOSS, returncode=1))
        monkeypatch.setattr(network, "_tcp_latency", lambda *a, **k: 5.0)
        result = network._check_ping(ping_cfg(count=3), "203.0.113.7")
        assert result.severity is Severity.CRITICAL
        assert "100% packet loss" in result.message
        assert "unusable" not in result.message

    def test_timeout_is_critical(self, monkeypatch):
        monkeypatch.setattr(network, "run_command",
                            lambda *a, **k: fake_result(timed_out=True, returncode=-1))
        result = network._check_ping(ping_cfg(), "1.1.1.1")
        assert result.severity is Severity.CRITICAL
        assert "timed out" in result.message

    def test_healthy_reply_is_ok(self, monkeypatch):
        monkeypatch.setattr(network, "run_command", lambda *a, **k: fake_result(stdout=IPUTILS_OK))
        result = network._check_ping(ping_cfg(), "1.1.1.1")
        assert result.severity is Severity.OK
        assert result.details["avg_ms"] == pytest.approx(8.6, abs=0.1)

    def test_slow_reply_warns(self, monkeypatch):
        monkeypatch.setattr(network, "run_command", lambda *a, **k: fake_result(stdout=IPUTILS_SLOW))
        result = network._check_ping(ping_cfg(count=1), "1.1.1.1")
        assert result.severity is Severity.WARNING
        assert "slow" in result.message


class TestTcpCheck:
    @pytest.mark.parametrize("spec,expected", [
        ("1.1.1.1:443", ("1.1.1.1", 443)),
        ("db.internal:5432", ("db.internal", 5432)),
        ("[::1]:443", ("::1", 443)),
        ("::1:443", ("::1", 443)),
    ])
    def test_valid_specs(self, spec, expected):
        assert network._split_host_port(spec) == expected

    @pytest.mark.parametrize("spec", ["noport", "1.1.1.1:0", "1.1.1.1:70000", "1.1.1.1:", "[::1]"])
    def test_invalid_specs(self, spec):
        assert network._split_host_port(spec) == (None, None)

    def test_invalid_spec_is_an_error_result(self):
        cfg = Config(network=NetworkConfig(tcp_ports=["nope"]))
        result = network._check_tcp(cfg, "nope")
        assert result.severity is Severity.ERROR
        assert "invalid host:port" in result.message

    def test_connect_success(self, monkeypatch):
        monkeypatch.setattr(network, "_tcp_latency", lambda *a, **k: 7.5)
        cfg = Config(network=NetworkConfig(tcp_ports=["1.1.1.1:443"]))
        result = network._check_tcp(cfg, "1.1.1.1:443")
        assert result.severity is Severity.OK
        assert result.details["port"] == 443

    def test_connect_failure(self, monkeypatch):
        monkeypatch.setattr(network, "_tcp_latency", lambda *a, **k: None)
        cfg = Config(network=NetworkConfig(tcp_ports=["1.1.1.1:443"]))
        result = network._check_tcp(cfg, "1.1.1.1:443")
        assert result.severity is Severity.CRITICAL
        assert "cannot connect" in result.message


class TestDns:
    def test_system_resolver_success(self, monkeypatch):
        monkeypatch.setattr(network, "_resolve",
                            lambda host, server: network.ResolveOutcome("9.9.9.9", "system"))
        result = network._check_dns(Config(network=NetworkConfig(dns_host="google.com")))
        assert result.severity is Severity.OK
        assert "9.9.9.9" in result.message

    def test_system_resolver_failure(self, monkeypatch):
        monkeypatch.setattr(network, "_resolve",
                            lambda host, server: network.ResolveOutcome(None, "system", "boom"))
        result = network._check_dns(Config(network=NetworkConfig(dns_host="google.com")))
        assert result.severity is Severity.CRITICAL
        assert "boom" in result.message

    def test_configured_servers_all_ok(self, monkeypatch):
        monkeypatch.setattr(network, "_resolve",
                            lambda host, server: network.ResolveOutcome("1.2.3.4", "dig"))
        cfg = Config(network=NetworkConfig(dns_host="google.com", dns_servers=["8.8.8.8", "1.1.1.1"]))
        assert network._check_dns(cfg).severity is Severity.OK

    def test_configured_servers_partial_failure_warns(self, monkeypatch):
        def resolve(host, server):
            if server == "8.8.8.8":
                return network.ResolveOutcome("1.2.3.4", "dig")
            return network.ResolveOutcome(None, "dig", "SERVFAIL")
        monkeypatch.setattr(network, "_resolve", resolve)
        cfg = Config(network=NetworkConfig(dns_host="google.com", dns_servers=["8.8.8.8", "9.9.9.9"]))
        result = network._check_dns(cfg)
        assert result.severity is Severity.WARNING
        assert "9.9.9.9" in result.message

    def test_configured_servers_all_fail_is_critical(self, monkeypatch):
        monkeypatch.setattr(network, "_resolve",
                            lambda host, server: network.ResolveOutcome(None, "dig", "SERVFAIL"))
        cfg = Config(network=NetworkConfig(dns_host="google.com", dns_servers=["8.8.8.8"]))
        assert network._check_dns(cfg).severity is Severity.CRITICAL

    def test_missing_dig_falls_back_to_system_resolver(self, monkeypatch):
        """A missing ``dig`` must not be reported as 'all servers are broken'."""
        def resolve(host, server):
            if server:
                return network.ResolveOutcome(None, "none", "dig is not installed")
            return network.ResolveOutcome("5.6.7.8", "system")
        monkeypatch.setattr(network, "_resolve", resolve)
        cfg = Config(network=NetworkConfig(dns_host="google.com", dns_servers=["8.8.8.8"]))
        result = network._check_dns(cfg)
        assert result.severity is Severity.WARNING
        assert "dig is not installed" in result.message
        assert result.details["method"] == "system"

    def test_missing_dig_and_broken_system_resolver_is_critical(self, monkeypatch):
        def resolve(host, server):
            if server:
                return network.ResolveOutcome(None, "none", "dig is not installed")
            return network.ResolveOutcome(None, "system", "name resolution failed")
        monkeypatch.setattr(network, "_resolve", resolve)
        cfg = Config(network=NetworkConfig(dns_host="google.com", dns_servers=["8.8.8.8"]))
        result = network._check_dns(cfg)
        assert result.severity is Severity.CRITICAL
        assert "dig is not installed" in result.message

    def test_resolve_uses_socket_when_no_server(self, monkeypatch):
        monkeypatch.setattr(network.socket, "gethostbyname", lambda host: "1.2.3.4")
        assert network._resolve("google.com", None) == network.ResolveOutcome("1.2.3.4", "system")

    def test_resolve_reports_missing_dig(self, monkeypatch):
        monkeypatch.setattr(network, "run_command",
                            lambda *a, **k: fake_result(missing=True, returncode=-1))
        outcome = network._resolve("google.com", "8.8.8.8")
        assert outcome.address is None
        assert outcome.method == "none"
        assert "dig" in outcome.error

    def test_resolve_reports_empty_answer(self, monkeypatch):
        monkeypatch.setattr(network, "run_command", lambda *a, **k: fake_result(stdout="\n"))
        outcome = network._resolve("google.com", "8.8.8.8")
        assert outcome.address is None
        assert outcome.error == "empty answer"


class TestRunNetworkChecks:
    def test_one_result_per_probe(self, monkeypatch):
        monkeypatch.setattr(network, "run_command", lambda *a, **k: fake_result(stdout=IPUTILS_OK))
        monkeypatch.setattr(network, "_tcp_latency", lambda *a, **k: 3.0)
        monkeypatch.setattr(network, "_resolve",
                            lambda host, server: network.ResolveOutcome("1.2.3.4", "system"))
        cfg = Config(network=NetworkConfig(ping_hosts=["1.1.1.1", "8.8.8.8"], tcp_ports=["1.1.1.1:443"],
                                           dns_host="google.com"))
        results = network.run_network_checks(cfg)
        assert [(r.check, r.subject) for r in results] == [
            ("network.ping", "1.1.1.1"),
            ("network.ping", "8.8.8.8"),
            ("network.tcp", "1.1.1.1:443"),
            ("network.dns", "google.com"),
        ]
        assert all(r.severity is Severity.OK for r in results)

    def test_dns_skipped_when_host_empty(self, monkeypatch):
        monkeypatch.setattr(network, "run_command", lambda *a, **k: fake_result(stdout=IPUTILS_OK))
        cfg = Config(network=NetworkConfig(ping_hosts=[], tcp_ports=[], dns_host=""))
        assert network.run_network_checks(cfg) == []

    def test_one_crashing_probe_does_not_stop_the_others(self, monkeypatch):
        """Error isolation: a probe that raises becomes an ERROR result."""
        def flaky(argv, timeout=10.0, cwd=None):
            if "8.8.8.8" in argv:
                raise RuntimeError("boom")
            return fake_result(stdout=IPUTILS_OK)
        monkeypatch.setattr(network, "run_command", flaky)
        monkeypatch.setattr(network, "_resolve",
                            lambda host, server: network.ResolveOutcome("1.2.3.4", "system"))
        cfg = Config(network=NetworkConfig(ping_hosts=["1.1.1.1", "8.8.8.8"], tcp_ports=[],
                                           dns_host="google.com"))
        results = network.run_network_checks(cfg)
        by_check = {r.check: r for r in results}
        # The crashing probe is reported under its full area label...
        assert by_check["network.ping[8.8.8.8]"].severity is Severity.ERROR
        assert "boom" in by_check["network.ping[8.8.8.8]"].message
        # ...while the healthy probe and the DNS check still ran.
        assert by_check["network.ping"].severity is Severity.OK
        assert by_check["network.ping"].subject == "1.1.1.1"
        assert by_check["network.dns"].severity is Severity.OK
        assert len(results) == 3
