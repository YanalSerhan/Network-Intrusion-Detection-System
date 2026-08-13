"""
Statistics and maintenance SDK operations.

Data Setup:  Expects the composing class to own `_database_service` and
             `_statistics_sampler`.
Data Input:  Counter readings from the capture service.
Data Output: Persisted statistics snapshots and retention results.

Split from `database_operations` so neither module outgrows the 150-line limit
in ADR 4, and because these are periodic *write* operations driven by the
maintenance scheduler, not the read queries the API serves.
"""

from collections.abc import Callable
from typing import Any

from ..capture.models import CaptureStatus
from ..services.database import DatabaseService
from ..services.statistics_sampler import StatisticsSampler, build_snapshot_payload


class MaintenanceOperationsMixin:
    """Statistics sampling and retention surface of the SDK."""

    # What this mixin needs the composing class to provide. Declaring the
    # contract is what the module docstring's "Data Setup" line describes, and
    # stating it in types rather than prose means the type checker holds the
    # composed SDK to it instead of every call site carrying an ignore.
    _statistics_sampler: StatisticsSampler
    _database_service: DatabaseService
    get_capture_status: Callable[[], CaptureStatus]
    get_alert_statistics: Callable[[], dict[str, Any]]
    get_alert_breakdown: Callable[[], dict[str, Any]]

    def get_statistics_series(self, hours: int = 24) -> list[dict[str, Any]]:
        """
        Return counter snapshots for the dashboard trend chart.

        Args:
            hours: Length of the window to fetch.

        Returns:
            One dict per snapshot, oldest first.
        """
        return [
            {
                "captured_at": record.captured_at,
                "total_packets": record.total_packets,
                "total_alerts": record.total_alerts,
                "packets_per_second": record.packets_per_second,
                "alerts_by_severity": record.alerts_by_severity,
                "top_talkers": record.top_talkers,
            }
            for record in self._database_service.statistics.get_series(hours=hours)
        ]

    def record_statistics_snapshot(self) -> None:
        """
        Capture current counters as a statistics snapshot.

        Throughput is derived from the delta since the previous snapshot:
        `packets_captured` is cumulative, so storing it directly left
        `packets_per_second` at zero forever and the chart flat.
        """
        capture = self.get_capture_status()
        stats = self.get_alert_statistics()
        breakdown = self.get_alert_breakdown()

        payload = build_snapshot_payload(
            total_packets=capture.packets_captured,
            packets_per_second=self._statistics_sampler.sample(capture.packets_captured),
            alert_stats=stats,
            top_talkers=breakdown["top_talkers"],
        )
        self._database_service.statistics.record_snapshot(**payload)

    def prune_old_data(self) -> dict[str, int]:
        """
        Run a retention sweep now.

        Exposed so an operator can reclaim space immediately rather than
        waiting for the scheduler's hourly tick.

        Returns:
            Rows deleted, keyed by table name.
        """
        return self._database_service.prune()
