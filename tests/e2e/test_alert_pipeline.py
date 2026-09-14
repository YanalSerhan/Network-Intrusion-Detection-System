"""
End-to-end: what a replayed attack leaves behind once the dust settles.

The scenario suite next door checks *which* detectors fire. This one checks
that a firing detector produces an alert an analyst can act on — classified,
scored, backed by evidence, deduplicated, and still there after a restart.
"""

from network_defender.constants import MitreTactic, Severity
from network_defender.sdk.sdk import NetworkDefenderSDK
from tests.fixtures.pcaps import sample_pcap


def _replay_scan(sdk: NetworkDefenderSDK) -> None:
    """Replay the port-scan capture and flush the detector windows."""
    sdk.start_capture_from_pcap(sample_pcap("tcp_port_scan"))
    sdk._detection_service.evaluate_detectors()


def test_alert_carries_everything_an_analyst_needs(running_sdk: NetworkDefenderSDK) -> None:
    """Severity, MITRE tactic, confidence and evidence are all populated."""
    _replay_scan(running_sdk)

    alert = next(
        a for a in running_sdk.list_alerts() if a.rule_triggered == "TcpPortScanDetector"
    )
    assert alert.severity is Severity.HIGH
    assert alert.tactic is MitreTactic.RECONNAISSANCE
    assert 0.0 < alert.confidence <= 1.0
    assert alert.evidence["unique_ports"] >= 15
    assert alert.src_ip is not None


def test_evidence_packets_are_stored_with_the_alert(running_sdk: NetworkDefenderSDK) -> None:
    """A rule match keeps the packet that triggered it, for later inspection."""
    _replay_scan(running_sdk)

    rule_alert = next(a for a in running_sdk.list_alerts() if a.rule_triggered == "TCP Port Scan")
    packets = running_sdk.get_alert_packets(rule_alert.alert_id)
    assert packets
    assert packets[0].src_ip == rule_alert.src_ip


def test_forty_matching_packets_are_one_alert_before_dedup_sees_them(
    running_sdk: NetworkDefenderSDK,
) -> None:
    """A scan is one alert because the rule fires once, not because dedup caught it."""
    _replay_scan(running_sdk)

    rule_alerts = [a for a in running_sdk.list_alerts() if a.rule_triggered == "TCP Port Scan"]
    assert len(rule_alerts) == 1
    # occurrences == 1 is the assertion, not an incidental detail: the rule
    # used to fire on every packet past the fifteenth and lean on
    # deduplication to clean up after it. Suppressing twenty-five alerts is
    # not the same as not raising them, because dedup's window is finite and
    # its key is not the rule's window.
    assert rule_alerts[0].occurrences == 1
    assert running_sdk._alert_service.health_check()["alerts_suppressed"] == 0


def test_alerts_survive_the_process_that_raised_them(running_sdk: NetworkDefenderSDK) -> None:
    """Detection is worthless if the findings die with the sensor."""
    _replay_scan(running_sdk)
    before = len(running_sdk.list_alerts())
    assert before > 0

    running_sdk.stop()
    running_sdk.start_readonly()
    try:
        assert len(running_sdk.list_alerts()) == before
    finally:
        running_sdk.stop_readonly()
        running_sdk.start()  # the fixture stops it again on teardown


def test_statistics_reflect_the_replayed_traffic(running_sdk: NetworkDefenderSDK) -> None:
    """The dashboard's counters come from the same run, not a separate path."""
    _replay_scan(running_sdk)

    stats = running_sdk.get_alert_statistics()
    assert stats["total_alerts"] == len(running_sdk.list_alerts())
    assert running_sdk._detection_service.health_check()["packets_processed"] == 40
