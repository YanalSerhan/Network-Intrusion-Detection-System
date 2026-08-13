"""
Tests that every count-based detector fires *at* its threshold, not past it.

The configured number is a promise: "alert on 10 failed SSH connections"
should alert on the tenth, not the eleventh. Off-by-one here is invisible to
any test that feeds a comfortable excess — and the mutation spot check found
that `>=` could be weakened to `>` in most of these detectors without a
single assertion objecting.

Each detector is exercised at exactly the threshold and at one below it, so
both the boundary and the direction of the comparison are pinned.
"""

from datetime import UTC, datetime
from typing import Any

import pytest

from network_defender.constants import Protocol
from network_defender.detectors.base import BaseDetector
from network_defender.detectors.impl.brute_force import (
    HttpBruteForceConfig,
    HttpBruteForceDetector,
    SshBruteForceConfig,
    SshBruteForceDetector,
)
from network_defender.detectors.impl.floods import (
    IcmpFloodConfig,
    IcmpFloodDetector,
    SynFloodConfig,
    SynFloodDetector,
    UdpFloodConfig,
    UdpFloodDetector,
)
from network_defender.detectors.impl.heuristics import ArpSpoofingConfig, ArpSpoofingDetector
from network_defender.detectors.impl.movement import (
    DataExfiltrationConfig,
    DataExfiltrationDetector,
    LateralMovementConfig,
    LateralMovementDetector,
)
from network_defender.detectors.impl.port_scans import TcpPortScanConfig, TcpPortScanDetector
from network_defender.parser.models import HttpFields, ParsedPacket, TcpFlags

#: Small, so a test that miscounts by one is unmistakable.
THRESHOLD = 4

SRC = "192.168.1.50"


def _packet(**overrides: object) -> ParsedPacket:
    """A packet with the fields each detector keys on."""
    fields: dict[str, object] = {
        "timestamp": datetime.now(UTC),
        "src_ip": SRC,
        "dst_ip": "10.0.0.1",
        "src_port": 12345,
        "dst_port": 80,
        "protocol": Protocol.TCP,
        "length": 100,
        "raw_summary": "packet",
    }
    fields.update(overrides)
    return ParsedPacket(**fields)  # type: ignore[arg-type]


def _ssh() -> tuple[BaseDetector[Any], list[ParsedPacket]]:
    detector = SshBruteForceDetector(SshBruteForceConfig(connection_count_threshold=THRESHOLD))
    packet = _packet(dst_port=22, tcp_flags=TcpFlags(syn=True))
    return detector, [packet] * THRESHOLD


def _http() -> tuple[BaseDetector[Any], list[ParsedPacket]]:
    detector = HttpBruteForceDetector(HttpBruteForceConfig(connection_count_threshold=THRESHOLD))
    packet = _packet(protocol=Protocol.HTTP, http=HttpFields(method="POST", path="/admin/login"))
    return detector, [packet] * THRESHOLD


def _syn_flood() -> tuple[BaseDetector[Any], list[ParsedPacket]]:
    detector = SynFloodDetector(SynFloodConfig(syn_count_threshold=THRESHOLD))
    return detector, [_packet(tcp_flags=TcpFlags(syn=True))] * THRESHOLD


def _udp_flood() -> tuple[BaseDetector[Any], list[ParsedPacket]]:
    detector = UdpFloodDetector(UdpFloodConfig(udp_count_threshold=THRESHOLD))
    return detector, [_packet(protocol=Protocol.UDP)] * THRESHOLD


def _icmp_flood() -> tuple[BaseDetector[Any], list[ParsedPacket]]:
    detector = IcmpFloodDetector(IcmpFloodConfig(icmp_count_threshold=THRESHOLD))
    return detector, [_packet(protocol=Protocol.ICMP, dst_port=None)] * THRESHOLD


def _arp() -> tuple[BaseDetector[Any], list[ParsedPacket]]:
    detector = ArpSpoofingDetector(ArpSpoofingConfig(gratuitous_arp_threshold=THRESHOLD))
    return detector, [_packet(protocol=Protocol.ARP, dst_port=None)] * THRESHOLD


def _exfiltration() -> tuple[BaseDetector[Any], list[ParsedPacket]]:
    detector = DataExfiltrationDetector(DataExfiltrationConfig(bytes_out_threshold=THRESHOLD * 100))
    return detector, [_packet(length=100)] * THRESHOLD


def _lateral() -> tuple[BaseDetector[Any], list[ParsedPacket]]:
    detector = LateralMovementDetector(
        LateralMovementConfig(internal_connection_threshold=THRESHOLD)
    )
    return detector, [_packet(dst_ip=f"192.168.1.{host}") for host in range(10, 10 + THRESHOLD)]


def _port_scan() -> tuple[BaseDetector[Any], list[ParsedPacket]]:
    detector = TcpPortScanDetector(TcpPortScanConfig(unique_ports_threshold=THRESHOLD))
    return detector, [_packet(dst_port=port) for port in range(1000, 1000 + THRESHOLD)]


BUILDERS = {
    "ssh brute force": _ssh,
    "http brute force": _http,
    "syn flood": _syn_flood,
    "udp flood": _udp_flood,
    "icmp flood": _icmp_flood,
    "arp spoofing": _arp,
    "data exfiltration": _exfiltration,
    "lateral movement": _lateral,
    "tcp port scan": _port_scan,
}


@pytest.mark.parametrize("name", sorted(BUILDERS))
def test_the_threshold_itself_is_enough_to_alert(name: str) -> None:
    """"Alert at N" must mean the Nth event, not the (N+1)th."""
    detector, packets = BUILDERS[name]()
    for packet in packets:
        detector.ingest(packet)

    assert len(detector.evaluate()) == 1


@pytest.mark.parametrize("name", sorted(BUILDERS))
def test_one_short_of_the_threshold_stays_quiet(name: str) -> None:
    """The other half of the boundary: N-1 events are not yet a finding."""
    detector, packets = BUILDERS[name]()
    for packet in packets[:-1]:
        detector.ingest(packet)

    assert detector.evaluate() == []
