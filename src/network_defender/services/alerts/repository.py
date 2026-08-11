"""
Alert persistence port and in-memory adapter.

Data Setup:  InMemoryAlertRepository takes an optional record bound; the
             SQLAlchemy adapter (Milestone 9) will take a session factory.
Data Input:  Alert models to save or update.
Data Output: Persisted Alerts, query results, and aggregate counts.

Architecture
------------
`AlertRepository` is the port; the alert service depends only on it. Milestone 9
adds a SQLAlchemy adapter implementing the same interface, so swapping storage
requires zero changes to AlertService (Dependency Inversion Principle).
"""

from abc import ABC, abstractmethod
from collections import OrderedDict
from datetime import datetime
from uuid import UUID

from network_defender.constants import (
    ALERT_QUERY_DEFAULT_LIMIT,
    ALERT_STORE_MAX_RECORDS,
    AlertStatus,
    Severity,
)

from .models import Alert


class AlertRepository(ABC):
    """Persistence port for alerts. Adapters must not leak storage details."""

    @abstractmethod
    def save(self, alert: Alert) -> Alert:
        """Insert an alert (or update it if its ID already exists)."""

    @abstractmethod
    def get(self, alert_id: UUID) -> Alert | None:
        """Return the alert with this ID, or None if it is not stored."""

    @abstractmethod
    def list_alerts(
        self,
        severity: Severity | None = None,
        status: AlertStatus | None = None,
        since: datetime | None = None,
        limit: int = ALERT_QUERY_DEFAULT_LIMIT,
        offset: int = 0,
    ) -> list[Alert]:
        """Return stored alerts, newest first, filtered by the given criteria."""

    @abstractmethod
    def count(self, severity: Severity | None = None) -> int:
        """Return the number of stored alerts, optionally filtered by severity."""

    @abstractmethod
    def clear(self) -> None:
        """Remove every stored alert."""


class InMemoryAlertRepository(AlertRepository):
    """
    Process-local alert store backed by an insertion-ordered dict.

    Suitable for development, tests, and single-process deployments. Bounded by
    `max_records`: the oldest alert is evicted once the bound is exceeded, so
    memory cannot grow without limit during an alert storm.
    """

    def __init__(self, max_records: int = ALERT_STORE_MAX_RECORDS) -> None:
        """
        Initialise the store.

        Args:
            max_records: Maximum alerts retained before oldest-first eviction.
        """
        self._max_records = max_records
        self._alerts: OrderedDict[UUID, Alert] = OrderedDict()

    def save(self, alert: Alert) -> Alert:
        """Persist an alert, evicting the oldest record if the bound is hit."""
        self._alerts[alert.alert_id] = alert
        while len(self._alerts) > self._max_records:
            self._alerts.popitem(last=False)
        return alert

    def get(self, alert_id: UUID) -> Alert | None:
        """Return a single alert by ID."""
        return self._alerts.get(alert_id)

    def list_alerts(
        self,
        severity: Severity | None = None,
        status: AlertStatus | None = None,
        since: datetime | None = None,
        limit: int = ALERT_QUERY_DEFAULT_LIMIT,
        offset: int = 0,
    ) -> list[Alert]:
        """
        Return matching alerts sorted newest-first.

        Args:
            severity: Only alerts with this exact severity.
            status:   Only alerts in this triage status.
            since:    Only alerts raised at or after this timestamp.
            limit:    Maximum number of alerts to return.
            offset:   Number of matching alerts to skip (pagination).

        Returns:
            List of Alert models, newest first.
        """
        matches = [
            alert
            for alert in self._alerts.values()
            if (severity is None or alert.severity == severity)
            and (status is None or alert.status == status)
            and (since is None or alert.timestamp >= since)
        ]
        matches.sort(key=lambda a: a.timestamp, reverse=True)
        return matches[offset : offset + limit]

    def count(self, severity: Severity | None = None) -> int:
        """Return the number of stored alerts, optionally filtered by severity."""
        if severity is None:
            return len(self._alerts)
        return sum(1 for alert in self._alerts.values() if alert.severity == severity)

    def clear(self) -> None:
        """Remove every stored alert."""
        self._alerts.clear()
