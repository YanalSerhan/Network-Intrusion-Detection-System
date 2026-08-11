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

from typing import Any

from ..services.statistics_sampler import StatisticsSampler, build_snapshot_payload


class MaintenanceOperationsMixin:
    """Statistics sampling and retention surface of the SDK."""

    _statistics_sampler: StatisticsSampler

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
            for record in self._database_service.statistics.get_series(hours=hours)  # type: ignore[attr-defined]
        ]

    def record_statistics_snapshot(self) -> None:
        """
        Capture current counters as a statistics snapshot.

        Throughput is derived from the delta since the previous snapshot:
        `packets_captured` is cumulative, so storing it directly left
        `packets_per_second` at zero forever and the chart flat.
        """
        capture = self.get_capture_status()  # type: ignore[attr-defined]
        stats = self.get_alert_statistics()  # type: ignore[attr-defined]
        breakdown = self.get_alert_breakdown()  # type: ignore[attr-defined]

        payload = build_snapshot_payload(
            total_packets=capture.packets_captured,
            packets_per_second=self._statistics_sampler.sample(capture.packets_captured),
            alert_stats=stats,
            top_talkers=breakdown["top_talkers"],
        )
        self._database_service.statistics.record_snapshot(**payload)  # type: ignore[attr-defined]

    def prune_old_data(self) -> dict[str, int]:
        """
        Run a retention sweep now.

        Exposed so an operator can reclaim space immediately rather than
        waiting for the scheduler's hourly tick.

        Returns:
            Rows deleted, keyed by table name.
        """
        return self._database_service.prune()  # type: ignore[attr-defined,no-any-return]
