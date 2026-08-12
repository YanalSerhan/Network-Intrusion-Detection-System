"""
Read-side of the alert service.

Data Setup:  Mixed into AlertService, which supplies `self.repository`.
Data Input:  Query criteria from the API and the SDK.
Data Output: Stored Alert models.

These are pass-throughs by design. Callers ask the service, never the
repository, so swapping the in-memory store for SQL stays invisible to the API
and the query surface has one place to grow.
"""

from datetime import datetime
from uuid import UUID

from network_defender.constants import ALERT_QUERY_DEFAULT_LIMIT, AlertStatus, Severity

from .models import Alert
from .repository import AlertRepository


class AlertQueryMixin:
    """Query methods for AlertService."""

    repository: AlertRepository

    def get_alert(self, alert_id: UUID) -> Alert | None:
        """
        Return a single stored alert.

        Args:
            alert_id: Identifier of the alert to fetch.

        Returns:
            The Alert, or None if no alert has that ID.
        """
        return self.repository.get(alert_id)

    def list_alerts(
        self,
        severity: Severity | None = None,
        status: AlertStatus | None = None,
        since: datetime | None = None,
        limit: int = ALERT_QUERY_DEFAULT_LIMIT,
        offset: int = 0,
    ) -> list[Alert]:
        """
        Return stored alerts, newest first, matching the given criteria.

        Args:
            severity: Restrict to one severity, or None for all.
            status:   Restrict to one lifecycle status, or None for all.
            since:    Only alerts at or after this time.
            limit:    Maximum alerts to return.
            offset:   Alerts to skip, for pagination.

        Returns:
            Matching alerts, most recent first.
        """
        return self.repository.list_alerts(
            severity=severity, status=status, since=since, limit=limit, offset=offset
        )
