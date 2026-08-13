"""
Translation between ORM rows and domain models.

Data Setup:  No state; pure functions.
Data Input:  Domain models (Alert, ParsedPacket, Rule) or ORM records.
Data Output: The other representation.

Repositories return domain models, never live ORM instances: that keeps
SQLAlchemy out of the services and leaves the in-memory and SQL repositories
interchangeable behind one port.
"""

from typing import Any

from ..constants import AlertSource, AlertStatus, MitreTactic, Severity
from ..parser.models import ParsedPacket
from ..parser.projection import protocol_sections, scalar_fields
from ..services.alerts.models import Alert
from ..services.threat_intel.models import ThreatIntelResult
from .models import AlertRecord, PacketRecord

#: Domain fields copied verbatim in both directions.
_ALERT_FIELDS = (
    "alert_id",
    "timestamp",
    "last_seen",
    "rule_triggered",
    "src_ip",
    "dst_ip",
    "src_port",
    "dst_port",
    "protocol",
    "packet_summary",
    "description",
    "confidence",
    "occurrences",
    "evidence",
)


def alert_to_record(alert: Alert) -> AlertRecord:
    """
    Build an ORM row from a domain Alert.

    Enum fields are stored as their string values so the schema stays readable
    in a SQL client and survives an enum member being renamed in Python.
    """
    values: dict[str, Any] = {name: getattr(alert, name) for name in _ALERT_FIELDS}
    return AlertRecord(
        **values,
        severity=str(alert.severity),
        source=str(alert.source),
        status=str(alert.status),
        tactic=str(alert.tactic) if alert.tactic else None,
        technique=alert.technique,
        threat_intel=alert.threat_intel.model_dump(mode="json") if alert.threat_intel else None,
    )


def record_to_alert(record: AlertRecord) -> Alert:
    """Rebuild a domain Alert from an ORM row."""
    values: dict[str, Any] = {name: getattr(record, name) for name in _ALERT_FIELDS}
    return Alert(
        **values,
        # Stored as plain strings; the enums are str-valued so these coerce back.
        severity=Severity(record.severity),
        source=AlertSource(record.source),
        status=AlertStatus(record.status),
        tactic=MitreTactic(record.tactic) if record.tactic else None,
        technique=record.technique,
        threat_intel=(
            ThreatIntelResult.model_validate(record.threat_intel) if record.threat_intel else None
        ),
    )


def apply_alert_to_record(alert: Alert, record: AlertRecord) -> AlertRecord:
    """
    Copy a domain Alert onto an existing row, for in-place updates.

    Used when deduplication increments `occurrences` or enrichment attaches
    threat intel to an alert that is already persisted.
    """
    for name in _ALERT_FIELDS:
        setattr(record, name, getattr(alert, name))
    record.severity = str(alert.severity)
    record.source = str(alert.source)
    record.status = str(alert.status)
    record.tactic = str(alert.tactic) if alert.tactic else None
    record.technique = alert.technique
    threat_intel = alert.threat_intel
    record.threat_intel = threat_intel.model_dump(mode="json") if threat_intel else None
    return record


def packet_to_record(packet: ParsedPacket, alert_id: Any = None) -> PacketRecord:
    """
    Build an ORM row from a parsed packet, optionally linked to an alert.

    Protocol-specific sections (TCP flags, DNS, HTTP, TLS) go into a single
    JSON column rather than sparse per-protocol columns, which would leave most
    of every row NULL and require a migration for each new protocol.
    """
    return PacketRecord(
        alert_id=alert_id, **scalar_fields(packet), fields=protocol_sections(packet)
    )


def record_to_packet(record: PacketRecord) -> ParsedPacket:
    """Rebuild a ParsedPacket from an ORM row."""
    return ParsedPacket(
        timestamp=record.timestamp,
        src_ip=record.src_ip,
        dst_ip=record.dst_ip,
        src_port=record.src_port,
        dst_port=record.dst_port,
        protocol=record.protocol,
        length=record.length,
        raw_summary=record.raw_summary,
        **(record.fields or {}),
    )
