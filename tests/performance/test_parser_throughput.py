"""
Performance: how fast the parser turns raw packets into ParsedPackets.

The parser sits on the hot path — every captured packet goes through it
before any detector sees anything — so a regression here slows the whole
sensor down. The floor is deliberately far below the real figure; it is
there to catch an order-of-magnitude change, not to certify a number.
"""

from typing import Any

from scapy.layers.inet import IP, TCP
from scapy.layers.l2 import Ether

from network_defender.parser.parser import PacketParser
from tests.fixtures.benchmark import measure, report
from tests.fixtures.packets import CAPTURE_TIMESTAMP

#: Enough packets that per-run startup noise stops dominating the measurement.
PACKET_COUNT = 10_000

#: A conservative floor for a slow, shared CI runner.
MIN_PACKETS_PER_SECOND = 100


def _build_packets(count: int) -> list[Any]:
    """Build synthetic TCP/IP packets with unique source ports."""
    packets = []
    for i in range(count):
        packet = (
            Ether() / IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=1024 + (i % 60000), dport=80)
        )
        packet.time = CAPTURE_TIMESTAMP + i * 0.001
        packets.append(packet)
    return packets


def test_parser_sustains_the_throughput_floor(started_parser: PacketParser) -> None:
    """Parse 10 000 packets, and account for every one of them."""
    packets = _build_packets(PACKET_COUNT)

    rate = measure(PACKET_COUNT, lambda: [started_parser.parse(p) for p in packets])
    report("parser", rate)

    health = started_parser.health_check()
    assert health["packets_parsed"] == PACKET_COUNT
    assert health["packets_failed"] == 0
    assert rate.per_second >= MIN_PACKETS_PER_SECOND, (
        f"Parser throughput {rate.per_second:.0f} pkt/s is below the "
        f"{MIN_PACKETS_PER_SECOND} pkt/s floor."
    )
