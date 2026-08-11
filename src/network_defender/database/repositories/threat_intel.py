"""
Threat intel cache repository.

Data Setup:  Session factory injected via __init__.
Data Input:  ProviderResult objects and their TTL.
Data Output: Cached ProviderResults that survive a restart.

The in-memory cache is rebuilt empty on every deploy. With a 24h reputation TTL
and provider budgets of ~10 requests/minute, that means a restart spends its
first minutes re-asking about addresses it already knew. This table is the
durable tier behind it.
"""

from datetime import UTC, datetime, timedelta

from sqlalchemy import func, select
from sqlalchemy.orm import Session, sessionmaker

from ...services.threat_intel.models import ProviderResult
from ..engine import session_scope
from ..models import ThreatIntelCacheRecord


class ThreatIntelCacheRepository:
    """Durable, TTL-bounded store of provider responses."""

    def __init__(self, session_factory: sessionmaker[Session]) -> None:
        """
        Initialise the repository.

        Args:
            session_factory: Factory producing sessions bound to the engine.
        """
        self._session_factory = session_factory

    def get(self, provider: str, ip: str) -> ProviderResult | None:
        """
        Return a cached result if present and unexpired.

        Expired rows are deleted on read rather than left for the retention
        sweep, so a stale entry can never be served even once.

        Args:
            provider: Provider name.
            ip:       The looked-up address.

        Returns:
            The cached ProviderResult, or None.
        """
        statement = select(ThreatIntelCacheRecord).where(
            ThreatIntelCacheRecord.provider == provider,
            ThreatIntelCacheRecord.ip == ip,
        )
        with session_scope(self._session_factory) as session:
            record = session.scalars(statement).first()
            if record is None:
                return None
            if record.expires_at <= datetime.now(UTC):
                session.delete(record)
                return None
            return ProviderResult.model_validate(record.payload)

    def set(self, provider: str, ip: str, result: ProviderResult, ttl_seconds: float) -> None:
        """
        Store or refresh a cached result.

        Failed lookups are not cached: doing so would turn one transient outage
        into a full TTL of missing enrichment.

        Args:
            provider:    Provider name.
            ip:          The looked-up address.
            result:      The result to cache.
            ttl_seconds: How long it stays fresh.
        """
        if not result.succeeded:
            return

        now = datetime.now(UTC)
        payload = result.model_dump(mode="json")
        statement = select(ThreatIntelCacheRecord).where(
            ThreatIntelCacheRecord.provider == provider,
            ThreatIntelCacheRecord.ip == ip,
        )

        with session_scope(self._session_factory) as session:
            record = session.scalars(statement).first()
            if record is None:
                session.add(
                    ThreatIntelCacheRecord(
                        provider=provider,
                        ip=ip,
                        payload=payload,
                        fetched_at=now,
                        expires_at=now + timedelta(seconds=ttl_seconds),
                    )
                )
            else:
                record.payload = payload
                record.fetched_at = now
                record.expires_at = now + timedelta(seconds=ttl_seconds)

    def purge_expired(self) -> int:
        """
        Delete every entry past its TTL.

        Returns:
            Number of rows removed.
        """
        statement = select(ThreatIntelCacheRecord).where(
            ThreatIntelCacheRecord.expires_at <= datetime.now(UTC)
        )
        with session_scope(self._session_factory) as session:
            expired = list(session.scalars(statement))
            for record in expired:
                session.delete(record)
        return len(expired)

    def count(self) -> int:
        """Return the number of cached entries, expired or not."""
        with session_scope(self._session_factory) as session:
            return int(
                session.scalar(select(func.count()).select_from(ThreatIntelCacheRecord)) or 0
            )

    def clear(self) -> None:
        """Delete every cached entry."""
        with session_scope(self._session_factory) as session:
            for record in session.scalars(select(ThreatIntelCacheRecord)):
                session.delete(record)
