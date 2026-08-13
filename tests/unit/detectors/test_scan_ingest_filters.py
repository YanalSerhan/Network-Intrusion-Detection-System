"""
Tests for what the scan detectors decline to count.

Every case here was found by the mutation spot check: each corresponds to a
mutant that survived the existing suite, which is another way of saying the
suite asserted that a scan is detected without ever asserting that anything
else is not. A detector whose ingest filter is wired with `or` instead of
`and` still passes every "does it detect a scan?" test — and counts normal
traffic as reconnaissance in production.
"""

from datetime import UTC, datetime

import pytest

from network_defender.constants import Protocol
from network_defender.detectors.impl.port_scans import (
    SynScanConfig,
    SynScanDetector,
    TcpPortScanConfig,
    TcpPortScanDetector,
)
from network_defender.parser.models import ParsedPacket, TcpFlags

#: Low enough that a handful of packets would cross it if they were counted.
THRESHOLD = 3


def _packet(**overrides: object) -> ParsedPacket:
    """A TCP packet, with fields the tests need to vary."""
    fields: dict[str, object] = {
        "timestamp": datetime.now(UTC),
        "src_ip": "192.168.1.50",
        "dst_ip": "10.0.0.1",
        "src_port": 12345,
        "dst_port": 80,
        "protocol": Protocol.TCP,
        "length": 64,
        "tcp_flags": TcpFlags(syn=True),
        "raw_summary": "TCP",
    }
    fields.update(overrides)
    return ParsedPacket(**fields)  # type: ignore[arg-type]


@pytest.fixture()
def port_scan() -> TcpPortScanDetector:
    """A port scan detector that alerts after three distinct ports."""
    return TcpPortScanDetector(
        TcpPortScanConfig(unique_ports_threshold=THRESHOLD, time_window_seconds=10)
    )


@pytest.fixture()
def syn_scan() -> SynScanDetector:
    """A SYN scan detector that alerts after three distinct ports."""
    return SynScanDetector(
        SynScanConfig(unique_ports_threshold=THRESHOLD, time_window_seconds=10)
    )


def test_packets_without_a_destination_port_are_not_counted(
    port_scan: TcpPortScanDetector,
) -> None:
    """A port scan is about ports; a packet with none says nothing about them."""
    for _ in range(THRESHOLD * 2):
        port_scan.ingest(_packet(dst_port=None))

    assert port_scan.evaluate() == []


def test_packets_without_a_source_address_are_not_counted(
    port_scan: TcpPortScanDetector,
) -> None:
    """An alert has to blame someone, and None is not an attacker."""
    for port in range(1000, 1000 + THRESHOLD * 2):
        port_scan.ingest(_packet(src_ip=None, dst_port=port))

    assert port_scan.evaluate() == []


def test_non_tcp_traffic_is_not_counted(port_scan: TcpPortScanDetector) -> None:
    """UDP to many ports is a UDP sweep; a different detector's business."""
    for port in range(1000, 1000 + THRESHOLD * 2):
        port_scan.ingest(_packet(protocol=Protocol.UDP, dst_port=port))

    assert port_scan.evaluate() == []


def test_syn_ack_replies_are_not_a_syn_scan(syn_scan: SynScanDetector) -> None:
    """
    A busy server sends SYN-ACK to many ports as a matter of course.

    Counting them would make every load balancer look like a scanner — this
    is the half-open filter, and it is the whole point of the detector.
    """
    for port in range(1000, 1000 + THRESHOLD * 2):
        syn_scan.ingest(_packet(dst_port=port, tcp_flags=TcpFlags(syn=True, ack=True)))

    assert syn_scan.evaluate() == []


def test_established_traffic_is_not_a_syn_scan(syn_scan: SynScanDetector) -> None:
    """Data on an open connection carries no SYN at all."""
    for port in range(1000, 1000 + THRESHOLD * 2):
        syn_scan.ingest(_packet(dst_port=port, tcp_flags=TcpFlags(ack=True, psh=True)))

    assert syn_scan.evaluate() == []


def test_packets_with_no_tcp_flags_are_not_a_syn_scan(syn_scan: SynScanDetector) -> None:
    """A truncated capture can leave the flags unparsed; that is not evidence."""
    for port in range(1000, 1000 + THRESHOLD * 2):
        syn_scan.ingest(_packet(dst_port=port, tcp_flags=None))

    assert syn_scan.evaluate() == []


def test_half_open_scans_are_still_detected(syn_scan: SynScanDetector) -> None:
    """The filters above must not have turned the detector off entirely."""
    for port in range(1000, 1000 + THRESHOLD):
        syn_scan.ingest(_packet(dst_port=port))

    alerts = syn_scan.evaluate()
    assert len(alerts) == 1
    assert alerts[0].evidence["unique_ports"] == THRESHOLD
