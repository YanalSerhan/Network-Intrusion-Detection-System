"""
Tests that one burst of traffic is one finding, for every detector.

Windows slide rather than clearing, so "report everything currently over the
threshold" would raise the same finding at every evaluation — one alert every
five seconds for a single scan. Deduplication downstream would fold those into
one row with an occurrence count in the dozens, and `occurrences` is supposed
to mean "times this was observed".

Driven through every committed capture rather than one, because the failure
would be per detector: a detector that forgot to re-arm on the rising edge
would look fine in its own unit test and flood a console in production.
"""

import pytest
from scapy.utils import rdpcap

from network_defender.detectors.models import DetectionAlert
from network_defender.parser.parser import PacketParser
from network_defender.services.detection import DetectionService
from network_defender.shared.paths import PROJECT_ROOT
from tests.fixtures.pcaps import sample_pcap

SCENARIOS = [
    "tcp_port_scan", "syn_flood", "udp_flood", "icmp_flood", "arp_spoofing",
    "dns_tunneling", "ssh_brute_force", "http_brute_force", "beaconing",
    "suspicious_port", "data_exfiltration", "lateral_movement", "benign",
]


def replay(scenario: str) -> tuple[list[DetectionAlert], list[DetectionAlert]]:
    """Replay a capture, then evaluate twice without feeding anything more."""
    service = DetectionService(config_dir=PROJECT_ROOT / "config")
    service.registry.load_detectors()
    parser = PacketParser()
    parser.start()

    for raw in rdpcap(str(sample_pcap(scenario))):
        parsed = parser.parse_safe(raw)
        if parsed is not None:
            service.process_packet(parsed)

    return service.evaluate_detectors(), service.evaluate_detectors()


@pytest.mark.parametrize("scenario", SCENARIOS)
def test_a_second_evaluation_repeats_nothing(scenario: str) -> None:
    first, second = replay(scenario)

    assert second == [], (
        f"{scenario} re-reported {[alert.detector_name for alert in second]} "
        f"on a second evaluation with no new traffic"
    )
    assert isinstance(first, list)


@pytest.mark.parametrize("scenario", SCENARIOS)
def test_each_finding_is_raised_once(scenario: str) -> None:
    """Two alerts from one detector about one host is the shape to catch."""
    first, _ = replay(scenario)

    findings = [(alert.detector_name, alert.src_ip, alert.dst_ip) for alert in first]

    assert len(findings) == len(set(findings)), f"{scenario} raised a duplicate finding"
