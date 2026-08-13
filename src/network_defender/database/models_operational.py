"""
ORM models for operational data: the threat intel cache and statistics.

Separate from `models.py`, which holds the investigation trail — alerts, their
packet evidence and the rules that raised them. These two are the system's own
bookkeeping: neither is evidence of anything on the network, both are safe to
truncate, and retention treats them differently for exactly that reason.
"""

from datetime import datetime
from typing import Any

from sqlalchemy import Index, String
from sqlalchemy.orm import Mapped, mapped_column

from .base import Base, JsonDict, UtcDateTime
from .column_widths import IP_ADDRESS_LENGTH, PROVIDER_LENGTH


class ThreatIntelCacheRecord(Base):
    """
    A cached provider response, surviving process restarts.

    The in-memory cache is rebuilt empty on every deploy; without this table a
    restart re-looks-up addresses already known, against provider budgets
    measured in tens of requests per minute.
    """

    __tablename__ = "threat_intel_cache"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    provider: Mapped[str] = mapped_column(String(PROVIDER_LENGTH), nullable=False)
    ip: Mapped[str] = mapped_column(String(IP_ADDRESS_LENGTH), nullable=False)
    payload: Mapped[dict[str, Any]] = mapped_column(JsonDict, nullable=False)
    fetched_at: Mapped[datetime] = mapped_column(UtcDateTime, nullable=False)
    expires_at: Mapped[datetime] = mapped_column(UtcDateTime, nullable=False, index=True)

    __table_args__ = (
        Index("uq_threat_intel_cache_provider_ip", "provider", "ip", unique=True),
    )


class StatisticsRecord(Base):
    """A point-in-time counter snapshot, used for dashboard trend charts."""

    __tablename__ = "statistics"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    captured_at: Mapped[datetime] = mapped_column(UtcDateTime, nullable=False, index=True)
    total_packets: Mapped[int] = mapped_column(default=0)
    total_alerts: Mapped[int] = mapped_column(default=0)
    packets_per_second: Mapped[float] = mapped_column(default=0.0)
    alerts_by_severity: Mapped[dict[str, int]] = mapped_column(JsonDict, default=dict)
    top_talkers: Mapped[dict[str, int]] = mapped_column(JsonDict, default=dict)
