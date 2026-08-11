"""
Alert API schemas.

Data Setup:  No I/O.
Data Input:  Domain Alert models from the SDK.
Data Output: JSON representations returned by /alerts.

Summary and detail are separate models on purpose. A list of 500 alerts should
not carry 500 copies of full threat-intel enrichment and evidence payloads;
the summary is what a table renders, the detail is what an investigation opens.
"""

from datetime import datetime
from typing import Any
from uuid import UUID

from pydantic import BaseModel, Field

from network_defender.constants import AlertSource, AlertStatus, MitreTactic, Severity
from network_defender.services.alerts.models import Alert
from network_defender.services.threat_intel.models import ThreatIntelResult

from .common import PageMeta


class AlertSummary(BaseModel):
    """Compact alert representation for list views."""

    alert_id: UUID = Field(description="Unique identifier.")
    timestamp: datetime = Field(description="When the alert was first raised (UTC).")
    last_seen: datetime = Field(description="When the most recent matching event occurred.")
    severity: Severity = Field(description="Severity level.")
    source: AlertSource = Field(description="Detector or rule engine.")
    rule_triggered: str = Field(description="Detector class or YAML rule name.")
    src_ip: str | None = Field(default=None, description="Source address.")
    dst_ip: str | None = Field(default=None, description="Destination address.")
    protocol: str | None = Field(default=None, description="Protocol involved.")
    confidence: float = Field(description="Confidence this is a true positive, 0.0-1.0.")
    tactic: MitreTactic | None = Field(default=None, description="MITRE ATT&CK tactic.")
    status: AlertStatus = Field(description="Triage status.")
    occurrences: int = Field(description="Identical events folded into this alert.")

    @classmethod
    def from_domain(cls, alert: Alert) -> "AlertSummary":
        """Project a domain Alert onto the summary shape."""
        return cls(**alert.model_dump(include=set(cls.model_fields)))


class AlertDetail(AlertSummary):
    """Full alert representation, including evidence and enrichment."""

    src_port: int | None = Field(default=None, description="Source port.")
    dst_port: int | None = Field(default=None, description="Destination port.")
    technique: str | None = Field(default=None, description="MITRE ATT&CK technique ID.")
    packet_summary: str = Field(default="", description="One-line description of the traffic.")
    description: str = Field(description="Why the alert fired.")
    evidence: dict[str, Any] = Field(
        default_factory=dict, description="Detector counters supporting the finding."
    )
    threat_intel: ThreatIntelResult | None = Field(
        default=None, description="External enrichment, if it has run."
    )

    @classmethod
    def from_domain(cls, alert: Alert) -> "AlertDetail":
        """Project a domain Alert onto the detail shape."""
        return cls(**alert.model_dump(include=set(cls.model_fields)))


class AlertStatusUpdate(BaseModel):
    """Request body for changing an alert's triage status."""

    status: AlertStatus = Field(description="The new triage status.")


class AlertPage(BaseModel):
    """A page of alert summaries."""

    items: list[AlertSummary] = Field(description="Alerts in this page, newest first.")
    meta: PageMeta = Field(description="Pagination metadata.")
