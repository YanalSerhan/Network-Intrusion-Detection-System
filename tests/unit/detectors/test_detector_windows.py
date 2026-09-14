"""
Tests that a detector's window is its own, and is a duration rather than a turn.

This is the suite that would have caught the defect Milestone 19 measured.
Until Milestone 21 every detector held state until `evaluate()` cleared it, so
the window was whatever the shared evaluation interval happened to be — five
seconds — while nine detectors were configured for sixty or more, and five of
them could not reach their thresholds at all.

Nothing here calls `evaluate()` on a timer, because that is the point: how
often a detector is asked and how much traffic it considers are now two
different things, and asking twice must not change the answer.
"""

from datetime import UTC, datetime

import pytest

from network_defender.constants import Protocol
from network_defender.detectors.impl.floods import UdpFloodConfig, UdpFloodDetector
from network_defender.detectors.impl.port_scans import TcpPortScanConfig, TcpPortScanDetector
from network_defender.parser.models import ParsedPacket

BASE = 1_700_000_000.0


def udp_packet(at: float) -> ParsedPacket:
    """One datagram to a fixed victim, captured at `at`."""
    return ParsedPacket(
        timestamp=datetime.fromtimestamp(at, tz=UTC),
        src_ip="45.155.205.233",
        dst_ip="192.168.1.10",
        dst_port=9999,
        protocol=Protocol.UDP,
        length=64,
        raw_summary="udp",
    )


def scan_packet(port: int, at: float) -> ParsedPacket:
    """One probe to `port`, captured at `at`."""
    return ParsedPacket(
        timestamp=datetime.fromtimestamp(at, tz=UTC),
        src_ip="45.155.205.233",
        dst_ip="192.168.1.10",
        dst_port=port,
        protocol=Protocol.TCP,
        length=54,
        raw_summary="tcp",
    )


@pytest.fixture()
def flood() -> UdpFloodDetector:
    """A flood detector configured exactly as the shipped one is: 200 per second."""
    return UdpFloodDetector(UdpFloodConfig(udp_count_threshold=200, time_window_seconds=1))


def test_traffic_inside_the_window_crosses_the_threshold(flood: UdpFloodDetector) -> None:
    for index in range(200):
        flood.ingest(udp_packet(BASE + index * 0.004))

    assert len(flood.evaluate()) == 1


def test_the_same_traffic_spread_wider_than_the_window_does_not(
    flood: UdpFloodDetector,
) -> None:
    """
    Spreading a flood out stops it being one.

    Two hundred datagrams a second is a flood; the same two hundred over ten
    seconds is twenty a second, and the configuration says that is not one.

    The old behaviour could not tell these apart, because it counted whatever
    had arrived since the last evaluation regardless of how long that was.
    """
    for index in range(200):
        flood.ingest(udp_packet(BASE + index * 0.05))

    assert flood.evaluate() == []


def test_asking_twice_does_not_change_the_answer(flood: UdpFloodDetector) -> None:
    """The evaluation interval is how often we look, not how far back we see."""
    for index in range(200):
        flood.ingest(udp_packet(BASE + index * 0.004))
    first = flood.evaluate()

    second = flood.evaluate()

    assert len(first) == 1
    assert second == [], "the same burst was reported twice"


def test_a_detector_uses_its_own_configured_window() -> None:
    """
    A ten-second scan window accumulates what a one-second window cannot.

    Both detectors see identical traffic; only `time_window_seconds` differs,
    which before this milestone made no difference at all.
    """
    probes = [scan_packet(1000 + index, BASE + index * 0.5) for index in range(20)]

    def scanner(window: int) -> TcpPortScanDetector:
        return TcpPortScanDetector(
            TcpPortScanConfig(unique_ports_threshold=15, time_window_seconds=window)
        )

    wide, narrow = scanner(window=10), scanner(window=1)
    for probe in probes:
        wide.ingest(probe)
        narrow.ingest(probe)

    assert len(wide.evaluate()) == 1
    assert narrow.evaluate() == []


def test_a_burst_that_stops_and_starts_again_is_two_findings(
    flood: UdpFloodDetector,
) -> None:
    """
    Two attacks an hour apart are two alerts, not one.

    The middle `evaluate()` is the realistic part and is load-bearing: a
    detector re-arms by *observing* the condition clear, and it observes on
    the service's timer. Nothing here would re-arm if the evaluation loop
    never ran between the bursts — see `detectors/edge.py`.
    """
    for index in range(200):
        flood.ingest(udp_packet(BASE + index * 0.004))
    first = flood.evaluate()

    flood.ingest(udp_packet(BASE + 1800))
    flood.evaluate()

    for index in range(200):
        flood.ingest(udp_packet(BASE + 3600 + index * 0.004))
    second = flood.evaluate()

    assert len(first) == 1
    assert len(second) == 1
