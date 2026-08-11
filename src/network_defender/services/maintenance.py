"""
Periodic background maintenance.

Data Setup:  Intervals from MaintenanceConfig; callbacks injected.
Data Input:  Wall-clock time.
Data Output: Statistics snapshots written, expired rows pruned.

Why this exists
---------------
Both jobs were implemented and reachable through the SDK, but nothing ever
called them. The consequences were silent and cumulative:

  * **No snapshots** meant the dashboard's throughput chart had no data to
    draw, permanently — the endpoint worked, the table stayed empty.
  * **No pruning** meant retention was configured but never enforced, so the
    database grew without bound. SQLite's failure mode when the disk fills is
    a corrupt file, not a clean error.

The two run on very different intervals. Snapshots are cheap and define the
chart's resolution, so they run every minute. Pruning issues DELETEs across
four tables and only needs to keep up with day-scale windows, so it runs
hourly — often enough to bound growth, rarely enough to stay off the hot path.

Each job is isolated: a failure in one is logged and the other still runs, and
neither can kill the loop. Maintenance must never be the reason a sensor stops
detecting.
"""

from collections.abc import Callable
from typing import Any

from ..shared.base import BaseService
from ..shared.config_models import MaintenanceConfig
from .evaluation_loop import PeriodicEvaluator


class MaintenanceService(BaseService):
    """Runs statistics sampling and retention pruning on background timers."""

    def __init__(
        self,
        record_snapshot: Callable[[], Any],
        prune: Callable[[], Any],
        config: MaintenanceConfig | None = None,
    ) -> None:
        """
        Initialise the service.

        Args:
            record_snapshot: Writes one statistics snapshot.
            prune:           Runs one retention sweep.
            config:          Intervals and enable flags; defaults if omitted.
        """
        super().__init__(service_name="MaintenanceService")
        self.config = config or MaintenanceConfig()
        self._record_snapshot = record_snapshot
        self._prune = prune

        self._snapshots = 0
        self._sweeps = 0
        self._failures = 0

        self._statistics_loop = PeriodicEvaluator(
            self.config.statistics_interval_seconds, self.run_statistics
        )
        self._retention_loop = PeriodicEvaluator(
            self.config.retention_interval_seconds, self.run_retention
        )

    def _do_start(self) -> None:
        """Start whichever jobs are enabled."""
        if self.config.statistics_enabled:
            self._statistics_loop.start()
        if self.config.retention_enabled:
            self._retention_loop.start()
        self.logger.info(
            "MaintenanceService started.",
            extra={
                "statistics_enabled": self.config.statistics_enabled,
                "retention_enabled": self.config.retention_enabled,
            },
        )

    def _do_stop(self) -> None:
        """Stop both loops."""
        self._statistics_loop.stop()
        self._retention_loop.stop()
        self.logger.info("MaintenanceService stopped.")

    def _do_health_check(self) -> dict[str, Any]:
        """Report what has run, so a silent scheduler is visible in /health."""
        return {
            "status": "ok",
            "snapshots_recorded": self._snapshots,
            "retention_sweeps": self._sweeps,
            "failures": self._failures,
            "statistics_running": self._statistics_loop.is_running,
            "retention_running": self._retention_loop.is_running,
        }

    def run_statistics(self) -> None:
        """
        Record one statistics snapshot.

        Public so a caller can force a sample without waiting for the timer,
        and so tests need not sleep.
        """
        try:
            self._record_snapshot()
            self._snapshots += 1
        except Exception as exc:  # noqa: BLE001 - maintenance must not stop detection
            self._failures += 1
            self.logger.error("Statistics snapshot failed: %s", exc)

    def run_retention(self) -> None:
        """
        Run one retention sweep.

        Public for the same reasons as `run_statistics`, and so an operator can
        reclaim space immediately via the SDK rather than waiting an hour.
        """
        try:
            removed = self._prune()
            self._sweeps += 1
            if isinstance(removed, dict) and any(removed.values()):
                self.logger.info("Retention sweep removed rows.", extra={"removed": removed})
        except Exception as exc:  # noqa: BLE001 - maintenance must not stop detection
            self._failures += 1
            self.logger.error("Retention sweep failed: %s", exc)
