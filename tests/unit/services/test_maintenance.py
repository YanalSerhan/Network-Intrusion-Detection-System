"""
Regression tests for the maintenance scheduler.

Both jobs existed and were reachable through the SDK, but nothing called them.
The failures were silent: the dashboard's throughput chart had no data to draw,
and retention never ran so the database grew without bound.

Statistics snapshots had a second defect — `packets_captured` is cumulative, so
recording it directly left `packets_per_second` at zero forever and the chart
flat even once snapshots existed.
"""

import time
from unittest.mock import MagicMock, patch

import pytest

from network_defender.sdk.sdk import NetworkDefenderSDK
from network_defender.services.maintenance import MaintenanceService
from network_defender.services.statistics_sampler import StatisticsSampler
from network_defender.shared.config_models import (
    AppConfig,
    CaptureConfig,
    MaintenanceConfig,
)
from network_defender.shared.rate_limit_models import RateLimitConfig

# --------------------------------------------------------------------------
# Throughput sampling
# --------------------------------------------------------------------------


def test_first_sample_has_no_rate_to_report() -> None:
    """There is no interval to divide by yet."""
    assert StatisticsSampler().sample(1_000, now=100.0) == 0.0


def test_rate_is_derived_from_the_delta() -> None:
    sampler = StatisticsSampler()
    sampler.sample(1_000, now=100.0)

    # 500 more packets over 10 seconds.
    assert sampler.sample(1_500, now=110.0) == 50.0


def test_consecutive_samples_track_a_changing_rate() -> None:
    sampler = StatisticsSampler()
    sampler.sample(0, now=0.0)

    assert sampler.sample(100, now=1.0) == 100.0
    assert sampler.sample(400, now=2.0) == 300.0
    assert sampler.sample(400, now=3.0) == 0.0  # traffic stopped


def test_counter_reset_does_not_produce_a_negative_rate() -> None:
    """Capture restarting sets the cumulative counter back to zero."""
    sampler = StatisticsSampler()
    sampler.sample(5_000, now=100.0)

    assert sampler.sample(10, now=110.0) == 0.0
    # The next sample uses the post-reset value as its baseline.
    assert sampler.sample(110, now=111.0) == 100.0


def test_zero_elapsed_time_does_not_divide_by_zero() -> None:
    sampler = StatisticsSampler()
    sampler.sample(100, now=50.0)
    assert sampler.sample(200, now=50.0) == 0.0


def test_reset_starts_a_new_baseline() -> None:
    sampler = StatisticsSampler()
    sampler.sample(1_000, now=100.0)
    sampler.reset()
    assert sampler.sample(2_000, now=110.0) == 0.0


# --------------------------------------------------------------------------
# Scheduler
# --------------------------------------------------------------------------


def _service(**overrides: object) -> tuple[MaintenanceService, MagicMock, MagicMock]:
    snapshot, prune = MagicMock(), MagicMock(return_value={})
    config = MaintenanceConfig(**overrides)  # type: ignore[arg-type]
    return MaintenanceService(snapshot, prune, config), snapshot, prune


def test_jobs_run_on_their_timers() -> None:
    """The regression: previously nothing ever invoked either job."""
    service, snapshot, prune = _service(
        statistics_interval_seconds=0.02, retention_interval_seconds=0.02
    )
    service.start()
    try:
        for _ in range(200):
            if snapshot.called and prune.called:
                break
            time.sleep(0.01)
    finally:
        service.stop()

    assert snapshot.called, "statistics snapshot never ran"
    assert prune.called, "retention sweep never ran"


def test_disabled_jobs_do_not_start() -> None:
    service, snapshot, prune = _service(
        statistics_enabled=False, retention_enabled=False
    )
    service.start()
    try:
        time.sleep(0.05)
        health = service.health_check()
        assert health["statistics_running"] is False
        assert health["retention_running"] is False
    finally:
        service.stop()

    snapshot.assert_not_called()
    prune.assert_not_called()


def test_a_failing_job_does_not_stop_the_other() -> None:
    """Maintenance must never be the reason a sensor stops detecting."""
    snapshot = MagicMock(side_effect=RuntimeError("database unavailable"))
    prune = MagicMock(return_value={})
    service = MaintenanceService(snapshot, prune, MaintenanceConfig())

    service.run_statistics()
    service.run_retention()

    health = service.health_check()
    assert health["failures"] == 1
    assert health["snapshots_recorded"] == 0
    assert health["retention_sweeps"] == 1


def test_health_counts_completed_work() -> None:
    service, _, _ = _service()
    service.run_statistics()
    service.run_statistics()
    service.run_retention()

    health = service.health_check()
    assert health["snapshots_recorded"] == 2
    assert health["retention_sweeps"] == 1
    assert health["failures"] == 0


def test_lifecycle_is_clean() -> None:
    service, _, _ = _service(
        statistics_interval_seconds=0.02, retention_interval_seconds=0.02
    )
    service.start()
    assert service.is_running
    assert service.health_check()["statistics_running"]

    service.stop()
    assert not service.is_running
    assert not service.health_check()["statistics_running"]


def test_intervals_must_be_positive() -> None:
    with pytest.raises(ValueError):
        MaintenanceConfig(statistics_interval_seconds=0)


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
