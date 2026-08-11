"""
Database-related SDK operations.

Data Setup:  Expects the composing class to own `_database_service`.
Data Input:  Query parameters and packets from consumers and the pipeline.
Data Output: Evidence packets, statistics snapshots and maintenance results.

ARCHITECTURE RULE: consumers never touch a repository or a session directly.
Everything goes through these SDK methods, which is what keeps the ORM out of
the presentation layer.
"""

from typing import Any
from uuid import UUID

from ..parser.models import ParsedPacket
from ..services.database import DatabaseService


class DatabaseOperationsMixin:
    """Persistence query and maintenance surface of the SDK."""

    _database_service: DatabaseService

    def get_alert_packets(self, alert_id: UUID) -> list[ParsedPacket]:
        """
        Return the packets retained as evidence for an alert.

        Args:
            alert_id: The alert to fetch evidence for.

        Returns:
            ParsedPacket models in capture order.
        """
        return self._database_service.packets.list_for_alert(alert_id)

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
        """Capture current counters as a statistics snapshot."""
        capture = self.get_capture_status()  # type: ignore[attr-defined]
        stats = self.get_alert_statistics()  # type: ignore[attr-defined]
        self._database_service.statistics.record_snapshot(
            total_packets=capture.packets_captured,
            total_alerts=stats["total_alerts"],
            alerts_by_severity=stats["by_severity"],
        )

    def get_loaded_rules(self) -> list[dict[str, Any]]:
        """
        Return the rule set currently loaded, as stored in the snapshot table.

        Returns:
            One dict per rule, ordered by name.
        """
        return [
            {
                "name": record.name,
                "severity": record.severity,
                "enabled": record.enabled,
                "window": record.window,
                "threshold": record.threshold,
                "group_by": record.group_by,
                "conditions": record.conditions,
                "source_path": record.source_path,
            }
            for record in self._database_service.rules.list_rules()
        ]

    def prune_old_data(self) -> dict[str, int]:
        """
        Run a retention sweep now.

        Returns:
            Rows deleted, keyed by table name.
        """
        return self._database_service.prune()

    def get_database_status(self) -> dict[str, Any]:
        """
        Return dialect, schema revision and row counts.

        Returns:
            Health dict suitable for the /health endpoint.
        """
        return self._database_service.health_check()
