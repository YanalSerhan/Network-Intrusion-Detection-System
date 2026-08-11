"""
Schemas for packets, rules, statistics, health and config.

Data Setup:  No I/O.
Data Input:  Domain models and SDK status dicts.
Data Output: JSON representations returned by the corresponding routers.
"""

from datetime import datetime
from typing import Any
from uuid import UUID

from pydantic import BaseModel, Field

from network_defender.constants import Severity
from network_defender.parser.models import ParsedPacket

from .common import PageMeta


class PacketView(BaseModel):
    """A packet retained as alert evidence."""

    timestamp: datetime = Field(description="Capture time (UTC).")
    src_ip: str | None = Field(default=None, description="Source address.")
    dst_ip: str | None = Field(default=None, description="Destination address.")
    src_port: int | None = Field(default=None, description="Source port.")
    dst_port: int | None = Field(default=None, description="Destination port.")
    protocol: str = Field(description="Highest-layer protocol detected.")
    length: int = Field(description="Total packet length in bytes.")
    raw_summary: str = Field(description="One-line human-readable description.")
    fields: dict[str, Any] = Field(
        default_factory=dict, description="Protocol sections (TCP flags, DNS, HTTP, TLS)."
    )

    @classmethod
    def from_domain(cls, packet: ParsedPacket) -> "PacketView":
        """Project a ParsedPacket onto the API shape."""
        sections = {
            name: getattr(packet, name).model_dump(mode="json")
            for name in ("tcp_flags", "dns", "http", "tls")
            if getattr(packet, name) is not None
        }
        return cls(
            timestamp=packet.timestamp,
            src_ip=packet.src_ip,
            dst_ip=packet.dst_ip,
            src_port=packet.src_port,
            dst_port=packet.dst_port,
            protocol=packet.protocol,
            length=packet.length,
            raw_summary=packet.raw_summary,
            fields=sections,
        )


class RuleView(BaseModel):
    """A loaded detection rule and its current state."""

    name: str = Field(description="Unique rule name.")
    severity: Severity = Field(description="Severity raised when the rule fires.")
    enabled: bool = Field(description="Whether the rule is currently evaluated.")
    window: int = Field(description="Aggregation window in seconds; 0 means single-packet.")
    threshold: int = Field(description="Matches required within the window before firing.")
    group_by: str = Field(description="Packet field the window aggregates on.")
    conditions: list[dict[str, Any]] = Field(description="Conditions, all of which must match.")
    source_path: str | None = Field(default=None, description="Originating YAML file.")


class PacketPage(BaseModel):
    """A page of retained packets."""

    items: list[PacketView] = Field(description="Packets in this page.")
    meta: PageMeta = Field(description="Pagination metadata.")


class RulePage(BaseModel):
    """A page of loaded rules."""

    items: list[RuleView] = Field(description="Rules in this page, ordered by name.")
    meta: PageMeta = Field(description="Pagination metadata.")


class RuleToggle(BaseModel):
    """Request body for enabling or disabling a rule."""

    enabled: bool = Field(description="Desired state.")


class RuleReloadResult(BaseModel):
    """Outcome of a rule reload."""

    status: str = Field(description="'success' when the reload completed.")
    loaded_rules_count: int = Field(description="Rules loaded after the reload.")


class TopTalker(BaseModel):
    """A busy source address and its alert count."""

    ip: str = Field(description="Source address.")
    alert_count: int = Field(description="Alerts attributed to this address.")


class StatisticsSummary(BaseModel):
    """Aggregate counters for the dashboard overview."""

    total_alerts: int = Field(description="Alerts currently stored.")
    alerts_by_severity: dict[str, int] = Field(description="Alert counts keyed by severity.")
    total_packets_retained: int = Field(description="Packets retained as evidence.")
    top_talkers: list[TopTalker] = Field(description="Busiest source addresses.")
    protocol_distribution: dict[str, int] = Field(description="Alert counts keyed by protocol.")


class StatisticsPoint(BaseModel):
    """One counter snapshot in a time series."""

    captured_at: datetime = Field(description="Snapshot time (UTC).")
    total_packets: int = Field(description="Packets processed at that moment.")
    total_alerts: int = Field(description="Alerts raised at that moment.")
    packets_per_second: float = Field(description="Throughput at that moment.")
    alerts_by_severity: dict[str, int] = Field(description="Severity breakdown.")


class ComponentHealth(BaseModel):
    """Health of one subsystem."""

    status: str = Field(description="'ok', 'degraded' or 'error'.")
    detail: dict[str, Any] = Field(default_factory=dict, description="Subsystem-specific fields.")


class HealthResponse(BaseModel):
    """Aggregate health payload."""

    status: str = Field(description="'ok' when every required component is healthy.")
    version: str = Field(description="Running application version.")
    components: dict[str, ComponentHealth] = Field(description="Per-component health.")


class LivenessResponse(BaseModel):
    """Minimal liveness payload: the process is up and serving."""

    status: str = Field(default="alive", description="Always 'alive' when served.")


class ConfigResponse(BaseModel):
    """Non-secret runtime configuration."""

    version: str = Field(description="Config schema version.")
    api: dict[str, Any] = Field(description="API server settings.")
    capture: dict[str, Any] = Field(description="Capture settings.")
    detection: dict[str, Any] = Field(description="Detection settings.")
    dashboard: dict[str, Any] = Field(description="Dashboard settings.")
    database: dict[str, Any] = Field(description="Database settings, URL redacted.")
    retention_days: int = Field(description="Configured retention window.")
    secrets_configured: dict[str, bool] = Field(
        description="Which credentials are set. Names and booleans only, never values."
    )


class AlertIdentifier(BaseModel):
    """Wrapper used where an endpoint echoes an alert identifier."""

    alert_id: UUID = Field(description="The alert this response concerns.")
