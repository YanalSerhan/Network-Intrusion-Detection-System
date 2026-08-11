"""
Dispatch of findings out of the detection service.

Data Setup:  Callbacks supplied by the detection service.
Data Input:  Detector alerts and rule matches.
Data Output: Invocations of the alert pipeline, under a fresh correlation ID.

Each finding gets its own correlation scope, opened at the moment the finding
exists. Everything downstream — scoring, deduplication, persistence,
notification, enrichment — logs under that ID, so one query returns the whole
life of an alert rather than fragments spread across services.

The "fired" log line is emitted inside the scope so the ID appears in the first
record about that finding, not only in whatever happens next.
"""

import logging
from collections.abc import Callable

from ..detectors.models import DetectionAlert
from ..observability import correlation_scope
from ..parser.models import ParsedPacket
from ..rules.models import Rule

logger = logging.getLogger("network_defender.security")


def dispatch_rule_match(
    rule: Rule,
    packet: ParsedPacket,
    callback: Callable[[Rule, ParsedPacket], None],
) -> None:
    """
    Send a signature match into the alert pipeline under a new correlation ID.

    Args:
        rule:     The rule that matched.
        packet:   The packet that satisfied it.
        callback: The alert-pipeline entry point.
    """
    with correlation_scope():
        logger.info(
            "Rule matched",
            extra={
                "event": "rule_match",
                "rule": rule.name,
                "severity": str(rule.severity),
                "src_ip": packet.src_ip,
                "dst_ip": packet.dst_ip,
            },
        )
        callback(rule, packet)


def dispatch_detector_alert(
    alert: DetectionAlert,
    callback: Callable[[DetectionAlert], None],
) -> None:
    """
    Send a heuristic detection into the alert pipeline under a new correlation ID.

    Args:
        alert:    The detection emitted by a detector.
        callback: The alert-pipeline entry point.
    """
    with correlation_scope():
        logger.info(
            "Detector fired",
            extra={
                "event": "detector_alert",
                "detector": alert.detector_name,
                "severity": str(alert.severity),
                "src_ip": alert.src_ip,
                "dst_ip": alert.dst_ip,
            },
        )
        callback(alert)
