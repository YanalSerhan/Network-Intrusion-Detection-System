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
from ..shared.config_models import AppConfig
from ..shared.secrets import describe_secrets


class DatabaseOperationsMixin:
    """Persistence query and maintenance surface of the SDK."""

    _database_service: DatabaseService
    _app_config: AppConfig

    def get_alert_packets(self, alert_id: UUID) -> list[ParsedPacket]:
        """
        Return the packets retained as evidence for an alert.

        Args:
            alert_id: The alert to fetch evidence for.

        Returns:
            ParsedPacket models in capture order.
        """
        return self._database_service.packets.list_for_alert(alert_id)

    def list_packets(
        self,
        alert_id: UUID | None = None,
        protocol: str | None = None,
        src_ip: str | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> list[ParsedPacket]:
        """
        Return retained packets matching the given filters.

        Args:
            alert_id: Restrict to evidence for one alert.
            protocol: Restrict to one protocol.
            src_ip:   Restrict to one source address.
            limit:    Maximum number of packets to return.
            offset:   Number of matching packets to skip.

        Returns:
            ParsedPacket models in capture order.
        """
        return self._database_service.packets.list_packets(
            alert_id=alert_id, protocol=protocol, src_ip=src_ip, limit=limit, offset=offset
        )

    def get_packet(self, packet_id: int) -> ParsedPacket | None:
        """
        Return a single retained packet by identifier.

        Args:
            packet_id: The packet row identifier.

        Returns:
            The ParsedPacket, or None if it does not exist.
        """
        return self._database_service.packets.get(packet_id)

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

    def get_alert_breakdown(self, top_talker_limit: int = 10) -> dict[str, Any]:
        """
        Return grouped alert counts for the statistics overview.

        Args:
            top_talker_limit: How many source addresses to include.

        Returns:
            Top talkers, protocol distribution and the retained packet count.
        """
        alerts = self._database_service.alerts
        return {
            "top_talkers": alerts.count_by("src_ip", limit=top_talker_limit),
            "protocol_distribution": alerts.count_by("protocol"),
            "packets_retained": self._database_service.packets.count(),
        }

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

    def get_app_config(self) -> AppConfig:
        """Return the validated application configuration."""
        return self._app_config

    @staticmethod
    def describe_configured_secrets(*names: str) -> dict[str, bool]:
        """
        Report which credentials are configured, without exposing any value.

        Args:
            *names: Environment variable names to check.

        Returns:
            Mapping of name -> True when a non-empty value is set.
        """
        return describe_secrets(*names)

    def get_database_status(self) -> dict[str, Any]:
        """
        Return dialect, schema revision and row counts.

        Returns:
            Health dict suitable for the /health endpoint.
        """
        return self._database_service.health_check()
