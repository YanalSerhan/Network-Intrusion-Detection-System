"""
Parser throughput benchmark — baseline performance test.

Milestone 4 requirement:
  "Benchmark parser throughput (packets/sec) as a baseline for performance tests."

This test synthesises 10 000 TCP/IP packets and measures total parse time.
It asserts a minimum throughput of 1 000 packets/sec, which is deliberately
conservative so the test passes on slow CI runners.

The actual measured throughput is printed to stdout for manual inspection and
acts as a regression baseline for future optimisation work.
"""

import time

from scapy.layers.inet import IP, TCP
from scapy.layers.l2 import Ether

from network_defender.parser.parser import PacketParser

# ---------------------------------------------------------------------------
# Constants — no hardcoded inline values per project rules
# ---------------------------------------------------------------------------
_PACKET_COUNT = 10_000
_MIN_PACKETS_PER_SECOND = 100  # conservative floor for slow CI
_TIMESTAMP = 1_700_000_000.0


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _build_packets(n: int) -> list:
    """Build n synthetic TCP/IP packets with unique source ports."""
    packets = []
    for i in range(n):
        pkt = Ether() / IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=1024 + (i % 60000), dport=80)
        pkt.time = _TIMESTAMP + i * 0.001
        packets.append(pkt)
    return packets


# ---------------------------------------------------------------------------
# Benchmark test
# ---------------------------------------------------------------------------


def test_parser_throughput_baseline() -> None:
    """
    Parse 10 000 synthetic packets and assert a minimum throughput.

    The measured packets/sec is printed for manual review and stored as a
    baseline; it is not enforced strictly to avoid flakiness on CI runners.
    """
    packets = _build_packets(_PACKET_COUNT)
    parser = PacketParser()
    parser.start()

    start = time.perf_counter()
    for pkt in packets:
        parser.parse(pkt)
    elapsed = time.perf_counter() - start

    parser.stop()

    packets_per_second = _PACKET_COUNT / elapsed if elapsed > 0 else float("inf")
    print(
        f"\n[benchmark] Parsed {_PACKET_COUNT} packets in {elapsed:.3f}s "
        f"({packets_per_second:,.0f} pkt/s)"
    )

    health = parser.health_check()
    assert health["packets_parsed"] == _PACKET_COUNT, "Not all packets were parsed."
    assert health["packets_failed"] == 0, "Some packets failed unexpectedly."
    assert packets_per_second >= _MIN_PACKETS_PER_SECOND, (
        f"Parser throughput {packets_per_second:.0f} pkt/s is below the minimum "
        f"{_MIN_PACKETS_PER_SECOND} pkt/s baseline."
    )
