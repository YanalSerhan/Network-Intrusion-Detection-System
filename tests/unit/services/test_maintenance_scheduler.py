"""Tests for the maintenance scheduler: timers, isolation and lifecycle."""

import time
from unittest.mock import MagicMock

import pytest

from network_defender.services.maintenance import MaintenanceService
from network_defender.shared.config_models import (
    MaintenanceConfig,
)

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
