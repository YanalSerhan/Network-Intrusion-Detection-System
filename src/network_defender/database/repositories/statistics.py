"""
Statistics snapshot repository.

Data Setup:  Session factory injected via __init__.
Data Input:  Counter snapshots taken on a timer.
Data Output: Time series backing the dashboard's trend charts.

Counters live in memory and reset on restart, so a dashboard built only on live
values can show "now" but never "this morning". Periodic snapshots give the
overview chart its history at a fixed, tiny write cost.
"""

from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session, sessionmaker

from ..engine import session_scope
from ..models_operational import StatisticsRecord

#: Default window for a dashboard trend query.
STATISTICS_DEFAULT_HOURS = 24


class StatisticsRepository:
    """Stores and queries point-in-time counter snapshots."""

    def __init__(self, session_factory: sessionmaker[Session]) -> None:
        """
        Initialise the repository.

        Args:
            session_factory: Factory producing sessions bound to the engine.
        """
        self._session_factory = session_factory

    def record_snapshot(
        self,
        total_packets: int = 0,
        total_alerts: int = 0,
        packets_per_second: float = 0.0,
        alerts_by_severity: dict[str, int] | None = None,
        top_talkers: dict[str, int] | None = None,
        captured_at: datetime | None = None,
    ) -> StatisticsRecord:
        """
        Persist one counter snapshot.

        Args:
            total_packets:      Packets processed since start.
            total_alerts:       Alerts raised since start.
            packets_per_second: Throughput at the moment of capture.
            alerts_by_severity: Alert counts keyed by severity.
            top_talkers:        Busiest source addresses and their counts.
            captured_at:        Snapshot time; defaults to now (UTC).

        Returns:
            The persisted StatisticsRecord.
        """
        record = StatisticsRecord(
            captured_at=captured_at or datetime.now(UTC),
            total_packets=total_packets,
            total_alerts=total_alerts,
            packets_per_second=packets_per_second,
            alerts_by_severity=alerts_by_severity or {},
            top_talkers=top_talkers or {},
        )
        with session_scope(self._session_factory) as session:
            session.add(record)
        return record

    def get_latest(self) -> StatisticsRecord | None:
        """Return the most recent snapshot, or None if none exist."""
        statement = select(StatisticsRecord).order_by(StatisticsRecord.captured_at.desc()).limit(1)
        with session_scope(self._session_factory) as session:
            return session.scalars(statement).first()

    def get_series(self, hours: int = STATISTICS_DEFAULT_HOURS) -> list[StatisticsRecord]:
        """
        Return snapshots from the last `hours`, oldest first.

        Args:
            hours: Length of the window to fetch.

        Returns:
            StatisticsRecord rows in chronological order.
        """
        cutoff = datetime.now(UTC) - timedelta(hours=hours)
        statement = (
            select(StatisticsRecord)
            .where(StatisticsRecord.captured_at >= cutoff)
            .order_by(StatisticsRecord.captured_at)
        )
        with session_scope(self._session_factory) as session:
            return list(session.scalars(statement))

    def summarise(self) -> dict[str, Any]:
        """
        Return aggregate figures over every stored snapshot.

        Returns:
            Peak and mean throughput plus the snapshot count.
        """
        with session_scope(self._session_factory) as session:
            row = session.execute(
                select(
                    func.count(StatisticsRecord.id),
                    func.max(StatisticsRecord.packets_per_second),
                    func.avg(StatisticsRecord.packets_per_second),
                )
            ).one()

        count, peak, mean = row
        return {
            "snapshots": int(count or 0),
            "peak_pps": float(peak or 0.0),
            "mean_pps": round(float(mean or 0.0), 2),
        }

    def clear(self) -> None:
        """Delete every stored snapshot."""
        with session_scope(self._session_factory) as session:
            for record in session.scalars(select(StatisticsRecord)):
                session.delete(record)
