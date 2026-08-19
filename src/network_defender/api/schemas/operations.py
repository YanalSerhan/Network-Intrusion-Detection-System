"""
Operational schemas: statistics, health and configuration.

Data Setup:  No I/O.
Data Input:  SDK status dicts and counter snapshots.
Data Output: JSON returned by /statistics, /health and /config.
"""

from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field


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
    retention: dict[str, Any] = Field(description="Per-table retention windows, in days.")
    secrets_configured: dict[str, bool] = Field(
        description="Which credentials are set. Names and booleans only, never values."
    )
