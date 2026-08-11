"""
Pydantic models for the Alert System.

Data Setup:  No external dependencies; constructed by the alert factory.
Data Input:  Fields derived from DetectionAlert objects and matched Rules.
Data Output: Validated Alert records persisted by the repository layer and
             serialised by the REST API / dashboard.
"""

from datetime import UTC, datetime
from typing import Any
from uuid import UUID, uuid4

from pydantic import BaseModel, Field

from network_defender.constants import (
    CONFIDENCE_MAX,
    CONFIDENCE_MIN,
    AlertSource,
    AlertStatus,
    MitreTactic,
    Severity,
)


def _utc_now() -> datetime:
    """Return the current time as a timezone-aware UTC datetime."""
    return datetime.now(UTC)


class Alert(BaseModel):
    """
    A single security alert produced by the detection engine or rule engine.

    This is the canonical alert representation for the whole system: it is what
    the repository persists, what the REST API returns, and what the dashboard
    renders. Detector-local `DetectionAlert` objects are normalised into this
    model by `factory.build_alert()`.
    """

    alert_id: UUID = Field(
        default_factory=uuid4, description="Globally unique identifier for this alert."
    )
    timestamp: datetime = Field(
        default_factory=_utc_now, description="Time the alert was first raised (UTC)."
    )
    severity: Severity = Field(description="Severity level of the detected activity.")
    source: AlertSource = Field(
        default=AlertSource.DETECTOR,
        description="Which subsystem raised the alert (detector or rule engine).",
    )
    rule_triggered: str = Field(
        description="Name of the detector or YAML rule that triggered this alert."
    )
    src_ip: str | None = Field(default=None, description="Source IP address of the activity.")
    dst_ip: str | None = Field(default=None, description="Destination IP address of the activity.")
    src_port: int | None = Field(default=None, ge=0, le=65535, description="Source port.")
    dst_port: int | None = Field(default=None, ge=0, le=65535, description="Destination port.")
    protocol: str | None = Field(default=None, description="Protocol associated with the activity.")
    packet_summary: str = Field(
        default="", description="One-line human-readable summary of the offending traffic."
    )
    description: str = Field(description="Human-readable explanation of why the alert fired.")
    confidence: float = Field(
        default=CONFIDENCE_MIN,
        ge=CONFIDENCE_MIN,
        le=CONFIDENCE_MAX,
        description="Confidence score in [0.0, 1.0] that this alert is a true positive.",
    )
    tactic: MitreTactic | None = Field(
        default=None, description="MITRE ATT&CK tactic ID associated with the detection."
    )
    technique: str | None = Field(
        default=None, description="MITRE ATT&CK technique ID (e.g. 'T1046')."
    )
    status: AlertStatus = Field(
        default=AlertStatus.NEW, description="Triage status of the alert."
    )
    occurrences: int = Field(
        default=1, ge=1, description="How many identical events this alert represents."
    )
    last_seen: datetime = Field(
        default_factory=_utc_now, description="Time the most recent identical event was seen (UTC)."
    )
    evidence: dict[str, Any] = Field(
        default_factory=dict, description="Counters and raw data supporting the detection."
    )

    def dedup_key(self) -> tuple[str, str, str, str]:
        """
        Return the tuple identifying "the same event" for deduplication purposes.

        Two alerts sharing a dedup key within the dedup window are collapsed
        into a single alert with an incremented occurrence counter.
        """
        return (
            self.rule_triggered,
            self.src_ip or "",
            self.dst_ip or "",
            str(self.severity),
        )


__all__ = ["Alert", "AlertStatus", "AlertSource"]
