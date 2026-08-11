"""Unit tests for MITRE ATT&CK mapping and confidence scoring."""

import pytest

from network_defender.constants import CONFIDENCE_MAX, CONFIDENCE_MIN, MitreTactic, Severity
from network_defender.detectors.registry import DetectorRegistry
from network_defender.services.alerts.confidence import score_alert, score_rule_match
from network_defender.services.alerts.mitre import DETECTOR_MITRE_MAP, lookup_mitre

# --------------------------------------------------------------------------
# MITRE mapping
# --------------------------------------------------------------------------


def test_every_registered_detector_has_a_mitre_mapping() -> None:
    registry = DetectorRegistry("config")
    registry.load_detectors()
    registered = {detector.name for detector in registry.detectors}
    assert registered, "no detectors were loaded"
    assert registered - set(DETECTOR_MITRE_MAP) == set()


def test_exact_detector_lookup() -> None:
    tactic, technique = lookup_mitre("TcpPortScanDetector")
    assert tactic is MitreTactic.RECONNAISSANCE
    assert technique == "T1046"


@pytest.mark.parametrize(
    ("rule_name", "expected"),
    [
        ("TCP Port Scan", MitreTactic.RECONNAISSANCE),
        ("SYN Flood", MitreTactic.IMPACT),
        ("SSH Brute Force", MitreTactic.CREDENTIAL_ACCESS),
        ("DNS Tunnel Suspicion", MitreTactic.COMMAND_AND_CONTROL),
        ("Large Exfiltration", MitreTactic.EXFILTRATION),
    ],
)
def test_rule_names_fall_back_to_keyword_mapping(rule_name: str, expected: MitreTactic) -> None:
    assert lookup_mitre(rule_name)[0] is expected


def test_unknown_source_degrades_gracefully() -> None:
    assert lookup_mitre("ThirdPartyDetector") == (None, None)


# --------------------------------------------------------------------------
# Confidence scoring
# --------------------------------------------------------------------------


def test_confidence_rises_with_evidence_magnitude() -> None:
    at_threshold = score_alert("TcpPortScanDetector", Severity.HIGH, {"unique_ports": 15})
    over = score_alert("TcpPortScanDetector", Severity.HIGH, {"unique_ports": 40})
    extreme = score_alert("TcpPortScanDetector", Severity.HIGH, {"unique_ports": 5000})
    assert at_threshold < over < extreme


def test_confidence_rises_with_severity() -> None:
    low = score_alert("SynFloodDetector", Severity.LOW, {"syn_count": 100})
    critical = score_alert("SynFloodDetector", Severity.CRITICAL, {"syn_count": 100})
    assert critical > low


def test_confidence_is_always_a_probability() -> None:
    extreme = score_alert("DataExfiltrationDetector", Severity.CRITICAL, {"bytes_out": 10**15})
    assert CONFIDENCE_MIN <= extreme <= CONFIDENCE_MAX


def test_flat_score_detector_ignores_evidence_magnitude() -> None:
    with_evidence = score_alert("SuspiciousPortDetector", Severity.MEDIUM, {"dst_port": 4444})
    without = score_alert("SuspiciousPortDetector", Severity.MEDIUM, {})
    assert with_evidence == without


def test_unmapped_detector_scores_on_severity_only() -> None:
    assert score_alert("ThirdPartyDetector", Severity.LOW, {"anything": 999}) == score_alert(
        "ThirdPartyDetector", Severity.LOW, {}
    )


@pytest.mark.parametrize("evidence", [{}, {"unique_ports": "many"}, {"unique_ports": True}, None])
def test_non_numeric_evidence_is_ignored(evidence: dict[str, object] | None) -> None:
    score = score_alert("TcpPortScanDetector", Severity.HIGH, evidence)
    assert score == score_alert("TcpPortScanDetector", Severity.HIGH, {})


def test_rule_matches_score_higher_than_heuristics() -> None:
    rule_score = score_rule_match(Severity.HIGH)
    heuristic = score_alert("TcpPortScanDetector", Severity.HIGH, {"unique_ports": 16})
    assert rule_score > heuristic
    assert score_rule_match(Severity.CRITICAL) > score_rule_match(Severity.INFO)
    assert score_rule_match(Severity.CRITICAL) <= CONFIDENCE_MAX
