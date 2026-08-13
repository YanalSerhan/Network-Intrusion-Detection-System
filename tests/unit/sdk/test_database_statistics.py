"""Tests for statistics snapshots, pruning and durability across an SDK restart."""

from pathlib import Path
from unittest.mock import MagicMock, patch

from network_defender.constants import Severity
from network_defender.detectors.models import DetectionAlert
from network_defender.sdk.sdk import NetworkDefenderSDK
from network_defender.shared.config_models import AppConfig, CaptureConfig
from network_defender.shared.rate_limit_models import RateLimitConfig
from tests.fixtures.constants import PUBLIC_IP


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
