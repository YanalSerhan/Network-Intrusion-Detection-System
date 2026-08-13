"""
Database-related SDK operations.

Data Setup:  Expects the composing class to own `_database_service`.
Data Input:  Query parameters from consumers and the pipeline.
Data Output: Evidence packets, rule snapshots and database status.

Periodic write operations (statistics sampling, retention) live in
`maintenance_operations`; this module holds the read side the API serves.

ARCHITECTURE RULE: consumers never touch a repository or a session directly.
Everything goes through these SDK methods, which is what keeps the ORM out of
the presentation layer.
"""

from typing import Any
from uuid import UUID

from ..database.mappers_rules import rule_record_to_dict
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
            rule_record_to_dict(record)
            for record in self._database_service.rules.list_rules()
        ]

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
