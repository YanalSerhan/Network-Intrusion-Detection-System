"""
Translation between ORM rows and domain models.

Data Setup:  No state; pure functions.
Data Input:  Domain models (Alert, ParsedPacket, Rule) or ORM records.
Data Output: The other representation.

Repositories return domain models, never live ORM instances. That keeps the
services free of SQLAlchemy — no detached-instance errors leaking into the alert
pipeline, no lazy loads firing after a session closes — and leaves the in-memory
and SQL repositories genuinely interchangeable behind the same port.
"""

from typing import Any

from ..constants import AlertSource, AlertStatus, MitreTactic, Severity
from ..parser.models import ParsedPacket
from ..rules.models import Rule
from ..services.alerts.models import Alert
from ..services.threat_intel.models import ThreatIntelResult
from .models import AlertRecord, PacketRecord, RuleRecord

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
    ti = alert.threat_intel
    record.threat_intel = ti.model_dump(mode="json") if ti else None
    return record


def packet_to_record(packet: ParsedPacket, alert_id: Any = None) -> PacketRecord:
    """
    Build an ORM row from a parsed packet, optionally linked to an alert.

    Protocol-specific sections (TCP flags, DNS, HTTP, TLS) go into a single
    JSON column rather than sparse per-protocol columns, which would leave most
    of every row NULL and require a migration for each new protocol.
    """
    fields = {
        section: getattr(packet, section).model_dump(mode="json")
        for section in ("tcp_flags", "dns", "http", "tls")
        if getattr(packet, section) is not None
    }
    return PacketRecord(
        alert_id=alert_id,
        timestamp=packet.timestamp,
        src_ip=packet.src_ip,
        dst_ip=packet.dst_ip,
        src_port=packet.src_port,
        dst_port=packet.dst_port,
        protocol=packet.protocol,
        length=packet.length,
        raw_summary=packet.raw_summary,
        fields=fields,
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


def rule_to_record(rule: Rule, source_path: str | None, loaded_at: Any) -> RuleRecord:
    """Snapshot a loaded YAML rule as an ORM row."""
    return RuleRecord(
        name=rule.name,
        severity=str(rule.severity),
        enabled=rule.enabled,
        window=rule.window,
        threshold=rule.threshold,
        group_by=rule.group_by,
        conditions=[condition.model_dump(mode="json") for condition in rule.conditions],
        source_path=source_path,
        loaded_at=loaded_at,
    )
