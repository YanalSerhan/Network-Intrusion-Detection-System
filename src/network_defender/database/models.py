"""
SQLAlchemy ORM models.

Data Setup:  Registered against the shared declarative Base.
Data Input:  Domain objects mapped by `database/mappers.py`.
Data Output: Persisted rows queried through the repository layer.

Indices target the queries the dashboard and API actually run: alerts filtered
by severity or status over a time range, and lookups by source IP during an
investigation. Composite indices are ordered with the equality column first and
the range column second, which is the order SQLite and PostgreSQL can both use
for a filter-then-sort without a separate sort step.
"""

from datetime import datetime
from typing import Any
from uuid import UUID, uuid4

from sqlalchemy import ForeignKey, Index, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .base import Base, JsonDict, UtcDateTime
from .types import GUID


class AlertRecord(Base):
    """A security alert, mirroring the domain `Alert` model."""

    __tablename__ = "alerts"

    alert_id: Mapped[UUID] = mapped_column(GUID(), primary_key=True, default=uuid4)
    timestamp: Mapped[datetime] = mapped_column(UtcDateTime, nullable=False, index=True)
    last_seen: Mapped[datetime] = mapped_column(UtcDateTime, nullable=False)
    severity: Mapped[str] = mapped_column(String(16), nullable=False)
    source: Mapped[str] = mapped_column(String(16), nullable=False)
    rule_triggered: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    src_ip: Mapped[str | None] = mapped_column(String(45), index=True)
    dst_ip: Mapped[str | None] = mapped_column(String(45), index=True)
    src_port: Mapped[int | None] = mapped_column()
    dst_port: Mapped[int | None] = mapped_column()
    protocol: Mapped[str | None] = mapped_column(String(16))
    packet_summary: Mapped[str] = mapped_column(Text, default="")
    description: Mapped[str] = mapped_column(Text, nullable=False)
    confidence: Mapped[float] = mapped_column(default=0.0)
    tactic: Mapped[str | None] = mapped_column(String(16))
    technique: Mapped[str | None] = mapped_column(String(16))
    status: Mapped[str] = mapped_column(String(24), nullable=False, index=True)
    occurrences: Mapped[int] = mapped_column(default=1)
    evidence: Mapped[dict[str, Any]] = mapped_column(JsonDict, default=dict)
    threat_intel: Mapped[dict[str, Any] | None] = mapped_column(JsonDict)

    packets: Mapped[list["PacketRecord"]] = relationship(
        back_populates="alert", cascade="all, delete-orphan"
    )

    __table_args__ = (
        # The dashboard's default view: "critical alerts, newest first".
        Index("ix_alerts_severity_timestamp", "severity", "timestamp"),
        # The triage queue: "everything still new, newest first".
        Index("ix_alerts_status_timestamp", "status", "timestamp"),
        # Investigation pivot: "everything this host did, in order".
        Index("ix_alerts_src_ip_timestamp", "src_ip", "timestamp"),
    )


class PacketRecord(Base):
    """
    A packet retained as evidence for an alert.

    Only alert-linked packets are stored. Persisting every parsed packet would
    mean ~860M rows/day at the 10k pps target; full traffic belongs in PCAP.
    """

    __tablename__ = "packets"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    alert_id: Mapped[UUID | None] = mapped_column(
        GUID(), ForeignKey("alerts.alert_id", ondelete="CASCADE"), index=True
    )
    timestamp: Mapped[datetime] = mapped_column(UtcDateTime, nullable=False, index=True)
    src_ip: Mapped[str | None] = mapped_column(String(45), index=True)
    dst_ip: Mapped[str | None] = mapped_column(String(45))
    src_port: Mapped[int | None] = mapped_column()
    dst_port: Mapped[int | None] = mapped_column()
    protocol: Mapped[str] = mapped_column(String(16), nullable=False)
    length: Mapped[int] = mapped_column(nullable=False)
    raw_summary: Mapped[str] = mapped_column(Text, default="")
    fields: Mapped[dict[str, Any]] = mapped_column(JsonDict, default=dict)

    alert: Mapped["AlertRecord | None"] = relationship(back_populates="packets")


class RuleRecord(Base):
    """A YAML detection rule, snapshotted so the UI can list what is loaded."""

    __tablename__ = "rules"

    name: Mapped[str] = mapped_column(String(128), primary_key=True)
    severity: Mapped[str] = mapped_column(String(16), nullable=False)
    enabled: Mapped[bool] = mapped_column(default=True, index=True)
    window: Mapped[int] = mapped_column(default=0)
    threshold: Mapped[int] = mapped_column(default=1)
    group_by: Mapped[str] = mapped_column(String(32), default="src_ip")
    conditions: Mapped[list[dict[str, Any]]] = mapped_column(JsonDict, default=list)
    source_path: Mapped[str | None] = mapped_column(Text)
    loaded_at: Mapped[datetime] = mapped_column(UtcDateTime, nullable=False)


class ThreatIntelCacheRecord(Base):
    """
    A cached provider response, surviving process restarts.

    The in-memory cache is rebuilt empty on every deploy; without this table a
    restart re-looks-up addresses already known, against provider budgets
    measured in tens of requests per minute.
    """

    __tablename__ = "threat_intel_cache"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    provider: Mapped[str] = mapped_column(String(64), nullable=False)
    ip: Mapped[str] = mapped_column(String(45), nullable=False)
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
