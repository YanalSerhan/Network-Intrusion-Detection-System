"""
Alert-related SDK operations, factored out to keep sdk.py focused and small.

Data Setup:  Expects the composing class to own an `_alert_service` attribute.
Data Input:  Query parameters from consumers (REST API, CLI, dashboard).
Data Output: Alert models and alert statistics.

ARCHITECTURE RULE: consumers never touch AlertService directly — they call
these SDK methods, exactly as they do for capture and parsing.
"""

from datetime import datetime
from typing import Any
from uuid import UUID

from ..constants import ALERT_QUERY_DEFAULT_LIMIT, AlertStatus, Severity
from ..detectors.models import DetectionAlert
from ..services.alerts import Alert, AlertService, NotificationHook


class AlertOperationsMixin:
    """Alert query and notification-registration surface of the SDK."""

    _alert_service: AlertService

    def _on_detection(self, detection: DetectionAlert) -> None:
        """
        Detection-service callback: funnel a detector alert into the pipeline.

        Returns None so it satisfies the detection service's callback contract.
        """
        self._alert_service.handle_detection(detection)

    def get_alert(self, alert_id: UUID) -> Alert | None:
        """
        Return a single alert by its UUID.

        Args:
            alert_id: The alert's unique identifier.

        Returns:
            The Alert, or None if no alert with that ID is stored.
        """
        return self._alert_service.get_alert(alert_id)

    def list_alerts(
        self,
        severity: Severity | None = None,
        status: AlertStatus | None = None,
        since: datetime | None = None,
        limit: int = ALERT_QUERY_DEFAULT_LIMIT,
        offset: int = 0,
    ) -> list[Alert]:
        """
        Return stored alerts, newest first.

        Args:
            severity: Restrict to this severity level.
            status:   Restrict to this triage status.
            since:    Restrict to alerts raised at or after this UTC timestamp.
            limit:    Maximum number of alerts to return.
            offset:   Number of matching alerts to skip (pagination).

        Returns:
            List of matching Alert models.
        """
        return self._alert_service.list_alerts(
            severity=severity, status=status, since=since, limit=limit, offset=offset
        )

    def get_alert_statistics(self) -> dict[str, Any]:
        """
        Return aggregate alert counts for the dashboard overview.

        Returns:
            Dict with the total alert count and a per-severity breakdown.
        """
        repository = self._alert_service.repository
        return {
            "total_alerts": repository.count(),
            "by_severity": {
                severity.value: repository.count(severity=severity) for severity in Severity
            },
        }

    def register_notification_hook(self, hook: NotificationHook) -> None:
        """
        Register an additional alert notification channel at runtime.

        Args:
            hook: Any NotificationHook implementation (email, webhook, Slack, …).
        """
        self._alert_service.dispatcher.register(hook)
