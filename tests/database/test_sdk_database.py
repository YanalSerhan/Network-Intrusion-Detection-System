"""Tests for the SDK persistence surface and end-to-end durability."""

from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from scapy.layers.inet import IP, TCP
from scapy.layers.l2 import Ether
from scapy.utils import wrpcap

from network_defender.constants import Severity
from network_defender.detectors.models import DetectionAlert
from network_defender.sdk.sdk import NetworkDefenderSDK
from network_defender.shared.config_models import AppConfig, CaptureConfig
from network_defender.shared.rate_limit_models import RateLimitConfig

from .conftest import PUBLIC_IP


@pytest.fixture()
def sdk() -> NetworkDefenderSDK:
    """An SDK bound to the per-test database from the suite-wide fixture."""
    cfg = AppConfig(capture=CaptureConfig(interface="eth0", max_packets_per_second=0))
    return NetworkDefenderSDK(app_config=cfg, rate_limit_config=RateLimitConfig(services={}))


@pytest.fixture()
def scan_pcap(tmp_path: Path) -> Path:
    """A 40-port SYN scan from a routable source address."""
    path = tmp_path / "scan.pcap"
    wrpcap(
        str(path),
        [
            Ether() / IP(src=PUBLIC_IP, dst="192.168.1.10") / TCP(dport=port, flags="S")
            for port in range(1000, 1040)
        ],
    )
    return path


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


def test_statistics_snapshot_and_series(sdk: NetworkDefenderSDK) -> None:
    assert sdk.get_statistics_series() == []

    sdk._on_detection(
        DetectionAlert(
            detector_name="TcpPortScanDetector",
            severity=Severity.HIGH,
            description="scan",
            src_ip=PUBLIC_IP,
        )
    )
    sdk.record_statistics_snapshot()

    series = sdk.get_statistics_series()
    assert len(series) == 1
    assert series[0]["total_alerts"] == 1
    assert series[0]["alerts_by_severity"]["high"] == 1


def test_prune_is_exposed_through_the_sdk(sdk: NetworkDefenderSDK) -> None:
    assert set(sdk.prune_old_data()) == {
        "packets",
        "alerts",
        "statistics",
        "threat_intel_cache",
    }


def test_alert_packets_for_an_unknown_alert_is_empty(sdk: NetworkDefenderSDK) -> None:
    from uuid import uuid4

    assert sdk.get_alert_packets(uuid4()) == []


@patch("network_defender.capture.service.AsyncSniffer")
def test_alerts_survive_an_sdk_restart(
    mock_sniffer: MagicMock, sdk: NetworkDefenderSDK, scan_pcap: Path
) -> None:
    """The whole point: findings outlive the process that made them."""
    mock_sniffer.return_value = MagicMock()
    sdk.start()
    sdk.start_capture_from_pcap(scan_pcap)
    sdk._detection_service.evaluate_detectors()
    before = {a.alert_id for a in sdk.list_alerts()}
    sdk.stop()
    assert before

    cfg = AppConfig(capture=CaptureConfig(interface="eth0", max_packets_per_second=0))
    restarted = NetworkDefenderSDK(app_config=cfg, rate_limit_config=RateLimitConfig(services={}))
    restarted.start()
    try:
        assert {a.alert_id for a in restarted.list_alerts()} == before
    finally:
        restarted.stop()
