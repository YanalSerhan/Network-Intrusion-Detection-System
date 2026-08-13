"""
End-to-end: replay each attack capture and check exactly what fires.

Every case drives the full production path — read the capture, classify the
protocol, parse the fields, ingest into the detectors, evaluate the windows,
persist an alert — through the SDK, the same entry point the CLI and REST API
use. Nothing between the file and the database is mocked.

The assertions compare the *whole* detector set, not just membership. An
extra detector firing is a false positive, and a suite that only ever checks
"did my detector fire?" is exactly the suite that never notices one.
"""

import pytest

from network_defender.sdk.sdk import NetworkDefenderSDK
from tests.fixtures.pcaps import sample_pcap

#: Capture name -> the detectors that must fire on it, and nothing else.
#: A port scan raises two by design: a half-open scan is also a port scan.
EXPECTED_DETECTIONS = {
    "tcp_port_scan": {"TcpPortScanDetector", "SynScanDetector"},
    "syn_flood": {"SynFloodDetector"},
    "udp_flood": {"UdpFloodDetector"},
    "icmp_flood": {"IcmpFloodDetector"},
    "arp_spoofing": {"ArpSpoofingDetector"},
    "dns_tunneling": {"DnsTunnelingDetector"},
    "ssh_brute_force": {"SshBruteForceDetector"},
    "http_brute_force": {"HttpBruteForceDetector"},
    "beaconing": {"BeaconingDetector"},
    "suspicious_port": {"SuspiciousPortDetector"},
    "lateral_movement": {"LateralMovementDetector"},
    "benign": set(),
}


def _detectors_fired(sdk: NetworkDefenderSDK) -> set[str]:
    """
    Return the names of the detectors credited with a stored alert.

    Signature rules and heuristic detectors both land in ``rule_triggered``;
    only detector names end in "Detector", and the YAML rules have their own
    test below.

    Args:
        sdk: A started SDK that has finished replaying a capture.

    Returns:
        The set of detector names that produced an alert.
    """
    return {
        alert.rule_triggered
        for alert in sdk.list_alerts()
        if alert.rule_triggered.endswith("Detector")
    }


@pytest.mark.parametrize("scenario", sorted(EXPECTED_DETECTIONS))
def test_capture_raises_exactly_the_expected_alerts(
    running_sdk: NetworkDefenderSDK, scenario: str
) -> None:
    """Each capture must raise its own detector's alert and no other."""
    running_sdk.start_capture_from_pcap(sample_pcap(scenario))
    running_sdk._detection_service.evaluate_detectors()

    assert _detectors_fired(running_sdk) == EXPECTED_DETECTIONS[scenario]


def test_benign_traffic_is_processed_but_never_alerts(running_sdk: NetworkDefenderSDK) -> None:
    """The negative case is only meaningful if the packets really went through."""
    running_sdk.start_capture_from_pcap(sample_pcap("benign"))
    running_sdk._detection_service.evaluate_detectors()

    assert running_sdk._detection_service.health_check()["packets_processed"] > 0
    assert running_sdk.list_alerts() == []


def test_signature_rules_fire_alongside_the_heuristics(running_sdk: NetworkDefenderSDK) -> None:
    """The YAML rule engine and the detectors are independent paths to an alert."""
    running_sdk.start_capture_from_pcap(sample_pcap("tcp_port_scan"))
    running_sdk._detection_service.evaluate_detectors()

    triggered = {alert.rule_triggered for alert in running_sdk.list_alerts()}
    assert "TCP Port Scan" in triggered
    assert "TcpPortScanDetector" in triggered
