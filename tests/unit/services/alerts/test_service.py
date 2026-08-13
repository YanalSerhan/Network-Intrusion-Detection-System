"""Unit tests for the alert factory and the AlertService pipeline."""

from network_defender.constants import AlertSource, MitreTactic, Severity
from network_defender.detectors.models import DetectionAlert
from network_defender.parser.models import ParsedPacket
from network_defender.rules.models import Rule
from network_defender.services.alerts.dedup import AlertDeduplicator
from network_defender.services.alerts.dispatcher import NotificationDispatcher
from network_defender.services.alerts.factory import build_alert, build_rule_alert
from network_defender.services.alerts.repository import InMemoryAlertRepository
from network_defender.services.alerts.service import AlertService
from tests.fixtures.hooks import RecordingHook

# --------------------------------------------------------------------------
# Factory
# --------------------------------------------------------------------------


def test_build_alert_attributes_and_scores_a_detection(detection: DetectionAlert) -> None:
    alert = build_alert(detection)
    assert alert.rule_triggered == "TcpPortScanDetector"
    assert alert.source is AlertSource.DETECTOR
    assert alert.tactic is MitreTactic.RECONNAISSANCE
    assert alert.technique == "T1046"
    assert alert.confidence > 0.5
    assert alert.evidence == {"unique_ports": 60}


def test_build_alert_enriches_from_the_triggering_packet(
    detection: DetectionAlert, packet: ParsedPacket
) -> None:
    alert = build_alert(detection, packet)
    assert alert.dst_ip == packet.dst_ip
    assert alert.dst_port == packet.dst_port
    assert alert.protocol == packet.protocol
    assert alert.packet_summary == packet.raw_summary


def test_detector_declared_tactic_wins(packet: ParsedPacket) -> None:
    detection = DetectionAlert(
        detector_name="TcpPortScanDetector",
        severity=Severity.HIGH,
        tactic=MitreTactic.IMPACT,
        description="d",
    )
    assert build_alert(detection, packet).tactic is MitreTactic.IMPACT


def test_build_rule_alert(rule: Rule, packet: ParsedPacket) -> None:
    alert = build_rule_alert(rule, packet)
    assert alert.source is AlertSource.RULE_ENGINE
    assert alert.rule_triggered == "TCP Port Scan"
    assert alert.tactic is MitreTactic.RECONNAISSANCE
    assert alert.severity is Severity.MEDIUM
    assert alert.evidence["conditions_matched"] == 1
    assert alert.packet_summary == packet.raw_summary


# --------------------------------------------------------------------------
# Service pipeline
# --------------------------------------------------------------------------


def _service(hook: RecordingHook | None = None) -> AlertService:
    return AlertService(
        repository=InMemoryAlertRepository(),
        deduplicator=AlertDeduplicator(),
        dispatcher=NotificationDispatcher([hook] if hook else []),
    )


def test_detection_is_persisted_and_notified(detection: DetectionAlert) -> None:
    hook = RecordingHook()
    service = _service(hook)

    alert = service.handle_detection(detection)
    assert alert is not None
    assert service.get_alert(alert.alert_id) is alert
    assert hook.received == [alert]


def test_duplicate_detection_is_suppressed(detection: DetectionAlert) -> None:
    hook = RecordingHook()
    service = _service(hook)

    first = service.handle_detection(detection)
    assert service.handle_detection(detection) is None
    assert first is not None and first.occurrences == 2
    assert len(hook.received) == 1
    assert len(service.list_alerts()) == 1


def test_rule_match_is_persisted(rule: Rule, packet: ParsedPacket) -> None:
    service = _service()
    alert = service.handle_rule_match(rule, packet)
    assert alert is not None
    assert service.list_alerts(severity=Severity.MEDIUM) == [alert]


def test_service_defaults_are_usable_without_configuration() -> None:
    service = AlertService()
    assert isinstance(service.repository, InMemoryAlertRepository)
    assert service.dispatcher.hooks == []


def test_lifecycle_resets_correlation_state(detection: DetectionAlert) -> None:
    service = _service()
    service.start()
    assert service.is_running

    service.handle_detection(detection)
    assert service.deduplicator.tracked_keys == 1

    service.stop()
    assert not service.is_running
    assert service.deduplicator.tracked_keys == 0


def test_health_check_reports_counters(detection: DetectionAlert) -> None:
    service = _service()
    service.start()
    service.handle_detection(detection)
    service.handle_detection(detection)

    health = service.health_check()
    assert health["alerts_stored"] == 1
    assert health["alerts_raised"] == 1
    assert health["alerts_suppressed"] == 1
    assert health["status"] == "ok"
    assert health["running"] is True
