"""
Builders for the domain objects tests construct most often.

Data Setup:  Nothing — every builder is a pure function.
Data Input:  Keyword overrides for the fields a given test actually cares about.
Data Output: A fully valid domain model.

These exist so a test can say what makes it different ("an alert from another
source IP") instead of restating every required field. Defaults are chosen to
be valid and uninteresting, so an assertion that fails points at the override
the test made rather than at incidental setup.
"""

from datetime import UTC, datetime

from network_defender.constants import Protocol, Severity
from network_defender.detectors.models import DetectionAlert
from network_defender.parser.models import ParsedPacket, TcpFlags
from network_defender.rules.models import Rule, RuleCondition
from network_defender.services.alerts.models import Alert

from .constants import INTERNAL_PEER_IP, PUBLIC_IP


def make_alert(
    rule_triggered: str = "TcpPortScanDetector",
    severity: Severity = Severity.HIGH,
    src_ip: str | None = PUBLIC_IP,
    dst_ip: str | None = INTERNAL_PEER_IP,
    timestamp: datetime | None = None,
    **overrides: object,
) -> Alert:
    """
    Build a persisted-shape Alert.

    Args:
        rule_triggered: Detector or rule name credited with the alert.
        severity:       Alert severity.
        src_ip:         Source address, or None for alerts without one.
        dst_ip:         Destination address, or None for alerts without one.
        timestamp:      First-seen time; defaults to now. ``last_seen`` follows
                        it so a freshly built alert is internally consistent.
        **overrides:    Any other Alert field.

    Returns:
        A validated Alert.
    """
    ts = timestamp or datetime.now(UTC)
    return Alert(
        timestamp=ts,
        last_seen=ts,
        severity=severity,
        rule_triggered=rule_triggered,
        src_ip=src_ip,
        dst_ip=dst_ip,
        description="test alert",
        **overrides,
    )


def make_detection(
    detector_name: str = "TcpPortScanDetector",
    severity: Severity = Severity.HIGH,
    src_ip: str | None = PUBLIC_IP,
    **overrides: object,
) -> DetectionAlert:
    """
    Build the raw DetectionAlert a detector emits before the alert service
    enriches, scores and deduplicates it.

    Args:
        detector_name: Name of the emitting detector.
        severity:      Severity the detector assigned.
        src_ip:        Address the detection is attributed to.
        **overrides:   Any other DetectionAlert field.

    Returns:
        A validated DetectionAlert.
    """
    overrides.setdefault("description", "TCP Port Scan detected: 60 unique ports scanned.")
    overrides.setdefault("evidence", {"unique_ports": 60})
    return DetectionAlert(
        detector_name=detector_name,
        severity=severity,
        src_ip=src_ip,
        **overrides,
    )


def make_packet(
    timestamp: datetime | None = None,
    src_ip: str = PUBLIC_IP,
    dst_ip: str = INTERNAL_PEER_IP,
    **overrides: object,
) -> ParsedPacket:
    """
    Build a parsed TCP packet with the transport fields populated.

    Args:
        timestamp:   Capture time; defaults to now.
        src_ip:      Source address.
        dst_ip:      Destination address.
        **overrides: Any other ParsedPacket field.

    Returns:
        A validated ParsedPacket.
    """
    overrides.setdefault("src_port", 51234)
    overrides.setdefault("dst_port", 443)
    overrides.setdefault("protocol", Protocol.TCP)
    overrides.setdefault("length", 74)
    overrides.setdefault("tcp_flags", TcpFlags(syn=True))
    overrides.setdefault("raw_summary", f"TCP {src_ip} -> {dst_ip}")
    return ParsedPacket(
        timestamp=timestamp or datetime.now(UTC),
        src_ip=src_ip,
        dst_ip=dst_ip,
        **overrides,
    )


def make_rule(
    name: str = "TCP Port Scan",
    severity: Severity = Severity.MEDIUM,
    **overrides: object,
) -> Rule:
    """
    Build a YAML-shaped Rule.

    Args:
        name:        Rule name.
        severity:    Severity emitted on match.
        **overrides: Any other Rule field, including ``conditions``.

    Returns:
        A validated Rule.
    """
    overrides.setdefault(
        "conditions", [RuleCondition(field="protocol", operator="equals", value="tcp")]
    )
    return Rule(name=name, severity=severity, **overrides)
