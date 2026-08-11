"""
Alert construction from detector and rule-engine output.

Data Setup:  No state; pure functions.
Data Input:  DetectionAlert objects from heuristic detectors, or a matched Rule
             plus the ParsedPacket that satisfied it.
Data Output: Fully populated Alert models (MITRE-attributed and scored) ready
             for deduplication and persistence.
"""

from network_defender.constants import AlertSource
from network_defender.detectors.models import DetectionAlert
from network_defender.parser.models import ParsedPacket
from network_defender.rules.models import Rule

from .confidence import score_alert, score_rule_match
from .mitre import lookup_mitre
from .models import Alert


def build_alert(detection: DetectionAlert, packet: ParsedPacket | None = None) -> Alert:
    """
    Normalise a detector's DetectionAlert into a canonical Alert.

    The detector's own tactic is preferred when it sets one; otherwise the
    MITRE mapping table supplies both tactic and technique.

    Args:
        detection: Alert emitted by a heuristic detector.
        packet:    Optional packet that triggered the detection, used to enrich
                   the alert with ports, protocol and a packet summary.

    Returns:
        A fully populated Alert with confidence and MITRE attribution.
    """
    mapped_tactic, technique = lookup_mitre(detection.detector_name)
    return Alert(
        timestamp=detection.timestamp,
        last_seen=detection.timestamp,
        severity=detection.severity,
        source=AlertSource.DETECTOR,
        rule_triggered=detection.detector_name,
        src_ip=detection.src_ip or (packet.src_ip if packet else None),
        dst_ip=detection.dst_ip or (packet.dst_ip if packet else None),
        src_port=packet.src_port if packet else None,
        dst_port=packet.dst_port if packet else None,
        protocol=packet.protocol if packet else None,
        packet_summary=packet.raw_summary if packet else "",
        description=detection.description,
        confidence=score_alert(
            detection.detector_name, detection.severity, detection.evidence
        ),
        tactic=detection.tactic or mapped_tactic,
        technique=technique,
        evidence=dict(detection.evidence),
    )


def build_rule_alert(rule: Rule, packet: ParsedPacket) -> Alert:
    """
    Build an Alert from a YAML rule that matched a packet.

    Args:
        rule:   The rule whose conditions all evaluated true.
        packet: The packet that satisfied the rule.

    Returns:
        A fully populated Alert attributed to the rule engine.
    """
    tactic, technique = lookup_mitre(rule.name)
    return Alert(
        timestamp=packet.timestamp,
        last_seen=packet.timestamp,
        severity=rule.severity,
        source=AlertSource.RULE_ENGINE,
        rule_triggered=rule.name,
        src_ip=packet.src_ip,
        dst_ip=packet.dst_ip,
        src_port=packet.src_port,
        dst_port=packet.dst_port,
        protocol=packet.protocol,
        packet_summary=packet.raw_summary,
        description=f"Rule '{rule.name}' matched: {len(rule.conditions)} condition(s) satisfied.",
        confidence=score_rule_match(rule.severity),
        tactic=tactic,
        technique=technique,
        evidence={"conditions_matched": len(rule.conditions), "window": rule.window},
    )
