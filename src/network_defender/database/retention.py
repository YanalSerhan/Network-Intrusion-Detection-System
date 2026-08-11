"""
Data retention and pruning.

Data Setup:  Retention windows injected via RetentionPolicy.
Data Input:  Wall-clock time.
Data Output: Rows deleted; counts reported per table.

Why retention is not optional
-----------------------------
Every table here grows monotonically. An unattended sensor fills its disk, and
SQLite's failure mode when the disk fills is a corrupt database, not a clean
error. Pruning is therefore part of normal operation, not a maintenance script
someone remembers to run.

Different data ages at different rates, so each table gets its own window:

  * **Packets** are bulky and only useful while the alert they support is being
    investigated — the shortest window.
  * **Alerts** are the audit trail and are kept longest.
  * **Cache entries** are governed by their own TTL; this only sweeps rows that
    are already expired.
  * **Statistics** are small per row but written continuously.

Deleting an alert cascades to its packets, so alert retention must be at least
as long as packet retention or evidence would outlive nothing.
"""

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from sqlalchemy import Delete, delete
from sqlalchemy.orm import Session, sessionmaker

from ..shared.base import LoggableMixin
from .engine import session_scope
from .models import AlertRecord, PacketRecord, StatisticsRecord, ThreatIntelCacheRecord


@dataclass(frozen=True)
class RetentionPolicy:
    """Per-table retention windows, in days."""

    alerts_days: int = 30
    packets_days: int = 7
    statistics_days: int = 90

    def __post_init__(self) -> None:
        """Reject windows that would delete evidence before its alert."""
        if self.packets_days > self.alerts_days:
            raise ValueError(
                "packets_days must not exceed alerts_days: deleting an alert cascades "
                "to its packets, so longer packet retention has no effect."
            )
        if min(self.alerts_days, self.packets_days, self.statistics_days) < 1:
            raise ValueError("Retention windows must be at least one day.")


class RetentionService(LoggableMixin):
    """Prunes rows that have outlived their retention window."""

    def __init__(
        self,
        session_factory: sessionmaker[Session],
        policy: RetentionPolicy | None = None,
    ) -> None:
        """
        Initialise the service.

        Args:
            session_factory: Factory producing sessions bound to the engine.
            policy:          Retention windows; defaults are used if omitted.
        """
        self._session_factory = session_factory
        self.policy = policy or RetentionPolicy()

    def prune(self, now: datetime | None = None) -> dict[str, int]:
        """
        Delete everything past its retention window.

        Args:
            now: Reference time; defaults to the current UTC time. Injectable
                so tests need not manipulate the clock.

        Returns:
            Rows deleted, keyed by table name.
        """
        reference = now or datetime.now(UTC)
        removed = {
            "packets": self._prune_packets(reference),
            "alerts": self._prune_alerts(reference),
            "statistics": self._prune_statistics(reference),
            "threat_intel_cache": self._prune_expired_cache(reference),
        }

        total = sum(removed.values())
        if total:
            self.logger.info("Retention sweep removed %d rows: %s", total, removed)
        return removed

    def _prune_packets(self, now: datetime) -> int:
        """Delete packet evidence older than the packet window."""
        cutoff = now - timedelta(days=self.policy.packets_days)
        return self._delete_where(delete(PacketRecord).where(PacketRecord.timestamp < cutoff))

    def _prune_alerts(self, now: datetime) -> int:
        """
        Delete alerts older than the alert window.

        Uses the ORM rather than a bulk DELETE so the packet cascade fires;
        a bulk statement bypasses relationship cascades and would orphan rows.
        """
        cutoff = now - timedelta(days=self.policy.alerts_days)
        with session_scope(self._session_factory) as session:
            stale = session.query(AlertRecord).filter(AlertRecord.timestamp < cutoff).all()
            for record in stale:
                session.delete(record)
            return len(stale)

    def _prune_statistics(self, now: datetime) -> int:
        """Delete statistics snapshots older than the statistics window."""
        cutoff = now - timedelta(days=self.policy.statistics_days)
        return self._delete_where(
            delete(StatisticsRecord).where(StatisticsRecord.captured_at < cutoff)
        )

    def _prune_expired_cache(self, now: datetime) -> int:
        """Delete threat intel cache entries already past their own TTL."""
        return self._delete_where(
            delete(ThreatIntelCacheRecord).where(ThreatIntelCacheRecord.expires_at <= now)
        )

    def _delete_where(self, statement: Delete) -> int:
        """Execute a bulk DELETE and return the affected row count."""
        with session_scope(self._session_factory) as session:
            result = session.execute(statement)
            # CursorResult exposes rowcount; the ORM's Result base type does not.
            return int(getattr(result, "rowcount", 0) or 0)
