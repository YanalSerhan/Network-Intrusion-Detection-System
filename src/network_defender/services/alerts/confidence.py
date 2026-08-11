"""
Confidence scoring for alerts.

Data Setup:  Static per-detector scoring profiles; no external dependencies.
Data Input:  Detector name, severity and the detector's evidence dictionary.
Data Output: A float confidence score in [0.0, 1.0] attached to every Alert.

Scoring model
-------------
    confidence = BASE
               + severity_rank * CONFIDENCE_SEVERITY_WEIGHT
               + magnitude_ratio * CONFIDENCE_EVIDENCE_WEIGHT

`magnitude_ratio` expresses how far past its threshold a detector fired: a
port scan touching 15 ports (threshold 15) is far less certain than one
touching 3,000. The ratio is clamped so a single enormous burst cannot make
a heuristic look deterministic. Signature (rule engine) matches bypass the
heuristic model entirely and use CONFIDENCE_RULE_ENGINE.
"""

from typing import Any

from network_defender.constants import (
    CONFIDENCE_BASE,
    CONFIDENCE_EVIDENCE_WEIGHT,
    CONFIDENCE_MAX,
    CONFIDENCE_MIN,
    CONFIDENCE_RULE_ENGINE,
    CONFIDENCE_SEVERITY_WEIGHT,
    SEVERITY_ORDER,
    Severity,
)

#: How many times over its own threshold a detector must fire before the
#: evidence term saturates. Keeps one huge burst from implying certainty.
SATURATION_MULTIPLE = 5.0

#: Detector name -> (evidence key holding the observed magnitude,
#:                   magnitude considered "just over threshold").
#: The reference values mirror the defaults in config/detectors.json.
DETECTOR_EVIDENCE_PROFILE: dict[str, tuple[str, float]] = {
    "TcpPortScanDetector": ("unique_ports", 15.0),
    "SynScanDetector": ("unique_ports", 10.0),
    "SynFloodDetector": ("syn_count", 100.0),
    "UdpFloodDetector": ("udp_count", 200.0),
    "IcmpFloodDetector": ("icmp_count", 50.0),
    "ArpSpoofingDetector": ("arp_count", 5.0),
    "DnsTunnelingDetector": ("count", 50.0),
    "SshBruteForceDetector": ("connection_count", 10.0),
    "HttpBruteForceDetector": ("request_count", 20.0),
    "BeaconingDetector": ("connection_count", 10.0),
    "DataExfiltrationDetector": ("bytes_out", 100_000_000.0),
    "LateralMovementDetector": ("unique_internal_destinations", 10.0),
}

#: Detectors whose evidence carries no magnitude (single-observation matches).
#: They score on severity alone.
FLAT_SCORE_DETECTORS = frozenset({"SuspiciousPortDetector"})


def _magnitude_ratio(detector_name: str, evidence: dict[str, Any]) -> float:
    """
    Return how strongly the evidence exceeds the detector's reference threshold.

    Args:
        detector_name: Name of the detector that produced the evidence.
        evidence:      The detector's evidence dictionary.

    Returns:
        Ratio in [0.0, 1.0]; 0.0 when no usable magnitude is present.
    """
    profile = DETECTOR_EVIDENCE_PROFILE.get(detector_name)
    if profile is None:
        return 0.0

    key, reference = profile
    raw = evidence.get(key)
    if not isinstance(raw, (int, float)) or isinstance(raw, bool) or reference <= 0:
        return 0.0

    excess = (float(raw) / reference) - 1.0
    if excess <= 0:
        return 0.0
    return min(excess / SATURATION_MULTIPLE, 1.0)


def score_alert(
    detector_name: str,
    severity: Severity,
    evidence: dict[str, Any] | None = None,
) -> float:
    """
    Compute the confidence that a heuristic detection is a true positive.

    Args:
        detector_name: Detector class name (used to select the scoring profile).
        severity:      Severity assigned by the detector.
        evidence:      Detector evidence counters; may be None or empty.

    Returns:
        Confidence score clamped to [CONFIDENCE_MIN, CONFIDENCE_MAX].
    """
    severity_rank = SEVERITY_ORDER.get(severity, 0)
    score = CONFIDENCE_BASE + (severity_rank * CONFIDENCE_SEVERITY_WEIGHT)

    if detector_name not in FLAT_SCORE_DETECTORS:
        ratio = _magnitude_ratio(detector_name, evidence or {})
        score += ratio * CONFIDENCE_EVIDENCE_WEIGHT

    return round(max(CONFIDENCE_MIN, min(score, CONFIDENCE_MAX)), 4)


def score_rule_match(severity: Severity) -> float:
    """
    Return the confidence for a signature (YAML rule) match.

    Signature matches are deterministic — the packet either satisfied every
    condition or it did not — so they score near the ceiling, nudged slightly
    by severity to keep informational matches from outranking critical ones.

    Args:
        severity: Severity declared on the matched rule.

    Returns:
        Confidence score clamped to [CONFIDENCE_MIN, CONFIDENCE_MAX].
    """
    max_rank = max(SEVERITY_ORDER.values())
    rank = SEVERITY_ORDER.get(severity, 0)
    penalty = (max_rank - rank) * CONFIDENCE_SEVERITY_WEIGHT
    return round(max(CONFIDENCE_MIN, min(CONFIDENCE_RULE_ENGINE - penalty, CONFIDENCE_MAX)), 4)
