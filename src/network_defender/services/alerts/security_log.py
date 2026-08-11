"""
Security-stream logging for alerts.

Data Setup:  No state.
Data Input:  Alerts that survived deduplication.
Data Output: One structured record per raised alert on the security stream.

This stream is the detection record — what an incident review reads months
later — so it is kept separate from application logs and carries the fields a
reviewer needs without opening the database: what fired, how confident, which
hosts, and which ATT&CK tactic.

The alert ID is included so a log line joins back to the stored alert, and the
correlation ID (added by the formatter) ties it to everything else that
happened while handling the same finding.
"""

from ...observability import get_security_logger
from .models import Alert


def log_alert_raised(alert: Alert) -> None:
    """
    Record a newly raised alert on the security stream.

    Args:
        alert: The alert that was persisted.
    """
    get_security_logger().info(
        "Alert raised",
        extra={
            "event": "alert_raised",
            "alert_id": str(alert.alert_id),
            "rule": alert.rule_triggered,
            "source": str(alert.source),
            "severity": str(alert.severity),
            "confidence": alert.confidence,
            "src_ip": alert.src_ip,
            "dst_ip": alert.dst_ip,
            "protocol": alert.protocol,
            "tactic": str(alert.tactic) if alert.tactic else None,
            "technique": alert.technique,
        },
    )


def log_alert_suppressed(alert: Alert, occurrences: int) -> None:
    """
    Record that a duplicate was folded into an existing alert.

    Logged at debug: during an alert storm this fires thousands of times, and
    the occurrence count on the stored alert already carries the information.

    Args:
        alert:       The alert the duplicate was merged into.
        occurrences: The updated occurrence count.
    """
    get_security_logger().debug(
        "Alert deduplicated",
        extra={
            "event": "alert_suppressed",
            "alert_id": str(alert.alert_id),
            "rule": alert.rule_triggered,
            "occurrences": occurrences,
        },
    )
