"""Tests for the SDK persistence surface: alerts, rules and evidence."""

from pathlib import Path
from unittest.mock import MagicMock, patch

from network_defender.sdk.sdk import NetworkDefenderSDK
from tests.fixtures.constants import PUBLIC_IP


def test_alerts_go_to_the_database_by_default(sdk: NetworkDefenderSDK) -> None:
    """Milestone 9's headline change: alerts are no longer held in memory."""
    from network_defender.database.repositories import SqlAlchemyAlertRepository

    assert isinstance(sdk._alert_service.repository, SqlAlchemyAlertRepository)


def test_database_status_is_reported(sdk: NetworkDefenderSDK) -> None:
    status = sdk.get_database_status()
    assert status["dialect"] == "sqlite"
    assert status["rows"]["alerts"] == 0


@patch("network_defender.capture.service.AsyncSniffer")
def test_health_includes_the_database_component(
    mock_sniffer: MagicMock, sdk: NetworkDefenderSDK
) -> None:
    mock_sniffer.return_value = MagicMock()
    sdk.start()
    try:
        assert sdk.get_health()["components"]["database"]["status"] == "ok"
    finally:
        sdk.stop()


@patch("network_defender.capture.service.AsyncSniffer")
def test_rule_snapshot_is_synced_on_start(
    mock_sniffer: MagicMock, sdk: NetworkDefenderSDK
) -> None:
    mock_sniffer.return_value = MagicMock()
    sdk.start()
    try:
        names = {rule["name"] for rule in sdk.get_loaded_rules()}
        assert "TCP Port Scan" in names
        assert all(rule["threshold"] >= 1 for rule in sdk.get_loaded_rules())
    finally:
        sdk.stop()


@patch("network_defender.capture.service.AsyncSniffer")
def test_rule_alerts_retain_packet_evidence(
    mock_sniffer: MagicMock, sdk: NetworkDefenderSDK, scan_pcap: Path
) -> None:
    mock_sniffer.return_value = MagicMock()
    sdk.start()
    try:
        sdk.start_capture_from_pcap(scan_pcap)

        rule_alerts = [a for a in sdk.list_alerts() if a.source == "rule_engine"]
        assert rule_alerts, "no rule alert was raised"

        evidence = sdk.get_alert_packets(rule_alerts[0].alert_id)
        assert len(evidence) == 1  # one packet per non-deduplicated alert
        assert evidence[0].src_ip == PUBLIC_IP
    finally:
        sdk.stop()


@patch("network_defender.capture.service.AsyncSniffer")
def test_deduplicated_occurrences_are_persisted(
    mock_sniffer: MagicMock, sdk: NetworkDefenderSDK, scan_pcap: Path
) -> None:
    """Regression: dedup mutates in place, which a durable store must be told about."""
    mock_sniffer.return_value = MagicMock()
    sdk.start()
    try:
        sdk.start_capture_from_pcap(scan_pcap)

        rule_alerts = [a for a in sdk.list_alerts() if a.source == "rule_engine"]
        assert len(rule_alerts) == 1
        assert rule_alerts[0].occurrences > 1
    finally:
        sdk.stop()
