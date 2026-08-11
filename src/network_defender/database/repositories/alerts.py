"""
SQL-backed alert repository.

Data Setup:  Session factory injected via __init__.
Data Input:  Domain Alert objects and query criteria.
Data Output: Domain Alert objects — never live ORM instances.

Implements the same `AlertRepository` port as the in-memory store, so the alert
service is unchanged by the switch to SQLite. `save()` is an upsert because the
alert pipeline re-saves the same record twice: once when deduplication bumps
the occurrence count, and again when background enrichment attaches threat
intel to an alert that is already persisted.
"""

from datetime import datetime
from uuid import UUID

from sqlalchemy import func, select
from sqlalchemy.orm import Session, sessionmaker

from ...constants import ALERT_QUERY_DEFAULT_LIMIT, AlertStatus, Severity
from ...services.alerts.models import Alert
from ...services.alerts.repository import AlertRepository
from ..engine import session_scope
from ..mappers import alert_to_record, apply_alert_to_record, record_to_alert
from ..models import AlertRecord


class SqlAlchemyAlertRepository(AlertRepository):
    """Persists alerts to any SQLAlchemy-supported database."""

    def __init__(self, session_factory: sessionmaker[Session]) -> None:
        """
        Initialise the repository.

        Args:
            session_factory: Factory producing sessions bound to the engine.
        """
        self._session_factory = session_factory

    def save(self, alert: Alert) -> Alert:
        """
        Insert an alert, or update it in place if its ID already exists.

        Args:
            alert: The alert to persist.

        Returns:
            The same domain Alert, for call chaining.
        """
        with session_scope(self._session_factory) as session:
            existing = session.get(AlertRecord, alert.alert_id)
            if existing is None:
                session.add(alert_to_record(alert))
            else:
                apply_alert_to_record(alert, existing)
        return alert

    def get(self, alert_id: UUID) -> Alert | None:
        """Return a single alert by ID, or None."""
        with session_scope(self._session_factory) as session:
            record = session.get(AlertRecord, alert_id)
            return record_to_alert(record) if record is not None else None

    def list_alerts(
        self,
        severity: Severity | None = None,
        status: AlertStatus | None = None,
        since: datetime | None = None,
        limit: int = ALERT_QUERY_DEFAULT_LIMIT,
        offset: int = 0,
    ) -> list[Alert]:
        """
        Return matching alerts, newest first.

        Filtering and ordering happen in SQL rather than in Python: an
        investigation may run against millions of rows, and loading them all to
        sort in memory would defeat the indices this schema exists to provide.

        Args:
            severity: Only alerts with this exact severity.
            status:   Only alerts in this triage status.
            since:    Only alerts raised at or after this timestamp.
            limit:    Maximum number of alerts to return.
            offset:   Number of matching alerts to skip (pagination).

        Returns:
            Domain Alert models, newest first.
        """
        statement = select(AlertRecord)
        if severity is not None:
            statement = statement.where(AlertRecord.severity == str(severity))
        if status is not None:
            statement = statement.where(AlertRecord.status == str(status))
        if since is not None:
            statement = statement.where(AlertRecord.timestamp >= since)

        statement = statement.order_by(AlertRecord.timestamp.desc()).limit(limit).offset(offset)

        with session_scope(self._session_factory) as session:
            return [record_to_alert(record) for record in session.scalars(statement)]

    def count(self, severity: Severity | None = None) -> int:
        """Return the number of stored alerts, optionally filtered by severity."""
        statement = select(func.count()).select_from(AlertRecord)
        if severity is not None:
            statement = statement.where(AlertRecord.severity == str(severity))

        with session_scope(self._session_factory) as session:
            return int(session.scalar(statement) or 0)

    def clear(self) -> None:
        """Delete every stored alert (and, by cascade, its packets)."""
        with session_scope(self._session_factory) as session:
            for record in session.scalars(select(AlertRecord)):
                session.delete(record)
