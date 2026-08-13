"""Tests for maintenance driven through the SDK: snapshots and retention."""

import time
from unittest.mock import MagicMock, patch

import pytest

from network_defender.sdk.sdk import NetworkDefenderSDK
from network_defender.shared.config_models import (
    AppConfig,
    CaptureConfig,
    MaintenanceConfig,
)
from network_defender.shared.rate_limit_models import RateLimitConfig

# --------------------------------------------------------------------------
# SDK integration
# --------------------------------------------------------------------------


@pytest.fixture()
def sdk() -> NetworkDefenderSDK:
    """An SDK with maintenance timers effectively disabled, driven manually."""
    config = AppConfig(
        capture=CaptureConfig(interface="eth0", max_packets_per_second=0),
        maintenance=MaintenanceConfig(
            statistics_interval_seconds=3600, retention_interval_seconds=3600
        ),
    )
    return NetworkDefenderSDK(app_config=config, rate_limit_config=RateLimitConfig(services={}))


@patch("network_defender.capture.service.AsyncSniffer")
def test_sdk_starts_and_stops_maintenance(
    mock_sniffer: MagicMock, sdk: NetworkDefenderSDK
) -> None:
    mock_sniffer.return_value = MagicMock()
    sdk.start()
    try:
        assert sdk.get_health()["components"]["maintenance"]["statistics_running"] is True
    finally:
        sdk.stop()

    assert sdk._maintenance_service.health_check()["statistics_running"] is False


def test_snapshots_record_real_throughput(sdk: NetworkDefenderSDK) -> None:
    """The chart was flat at zero because a cumulative counter was stored raw."""
    sdk._database_service.start()
    try:
        sdk._capture_service._packets_captured = 0
        sdk.record_statistics_snapshot()

        # Simulate traffic, then sample again with a known interval.
        sdk._capture_service._packets_captured = 1_000
        sdk._statistics_sampler._last_time = time.monotonic() - 10.0
        sdk.record_statistics_snapshot()

        series = sdk.get_statistics_series()
        assert len(series) == 2
        assert series[0]["packets_per_second"] == 0.0  # no baseline yet
        assert series[1]["packets_per_second"] > 0, "throughput is still flat at zero"
        assert series[1]["total_packets"] == 1_000
    finally:
        sdk._database_service.stop()


def test_snapshots_capture_top_talkers(sdk: NetworkDefenderSDK) -> None:
    from network_defender.constants import Severity
    from network_defender.detectors.models import DetectionAlert

    sdk._database_service.start()
    try:
        sdk._on_detection(
            DetectionAlert(
                detector_name="TcpPortScanDetector",
                severity=Severity.HIGH,
                description="scan",
                src_ip="45.155.205.233",
            )
        )
        sdk.record_statistics_snapshot()

        snapshot = sdk.get_statistics_series()[0]
        assert snapshot["top_talkers"] == {"45.155.205.233": 1}
        assert snapshot["alerts_by_severity"]["high"] == 1
    finally:
        sdk._database_service.stop()


def test_retention_runs_through_the_scheduler(sdk: NetworkDefenderSDK) -> None:
    sdk._database_service.start()
    try:
        sdk._maintenance_service.run_retention()
        assert sdk._maintenance_service.health_check()["retention_sweeps"] == 1
        assert sdk._maintenance_service.health_check()["failures"] == 0
    finally:
        sdk._database_service.stop()
