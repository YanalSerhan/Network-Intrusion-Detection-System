"""
Mapping between loaded rules and their database snapshot.

Data Setup:  None.
Data Input:  A Rule as loaded from YAML, or a snapshot row.
Data Output: A RuleRecord, or the flat dict the SDK exposes.

Separate from `mappers`, which maps the alert and packet trail. A rule
snapshot is not evidence: it records which rules were loaded when, so an
investigation can tell whether a rule existed at the time of an alert.
"""

from typing import Any

from ..rules.models import Rule
from .models import RuleRecord


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


def rule_record_to_dict(record: RuleRecord) -> dict[str, Any]:
    """
    Project a rule snapshot row onto the flat shape the SDK exposes.

    Args:
        record: A rule row read from the snapshot table.

    Returns:
        The rule's fields, ready for the API to serialise.
    """
    return {
        "name": record.name,
        "severity": record.severity,
        "enabled": record.enabled,
        "window": record.window,
        "threshold": record.threshold,
        "group_by": record.group_by,
        "conditions": record.conditions,
        "source_path": record.source_path,
    }
