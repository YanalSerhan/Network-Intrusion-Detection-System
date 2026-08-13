"""Integration tests: enrichment runs on a worker and never blocks detection."""

import time

from network_defender.constants import Severity
from network_defender.detectors.models import DetectionAlert
from network_defender.services.alerts.models import Alert
from network_defender.services.alerts.service import AlertService
from network_defender.services.threat_intel.service import ThreatIntelService
from network_defender.services.threat_intel.worker import EnrichmentWorker
from tests.fixtures.constants import PUBLIC_IP

# --------------------------------------------------------------------------
# Background worker
# --------------------------------------------------------------------------


class _RecordingService(ThreatIntelService):
    """TI service double that records which alerts it was asked to enrich."""

    def __init__(self) -> None:
        super().__init__(providers=[])
        self.seen: list[Alert] = []

    def enrich_alert(self, alert: Alert) -> None:
        self.seen.append(alert)


def _alert(ip: str = PUBLIC_IP) -> Alert:
    return Alert(severity=Severity.HIGH, rule_triggered="R", description="d", dst_ip=ip)


def test_worker_drains_queued_alerts() -> None:
    service = _RecordingService()
    worker = EnrichmentWorker(service)

    for _ in range(3):
        assert worker.submit(_alert()) is True
    assert worker.queue_depth == 3

    assert worker.drain() == 3
    assert len(service.seen) == 3


def test_worker_drops_alerts_when_the_queue_is_full() -> None:
    worker = EnrichmentWorker(_RecordingService(), max_queue_depth=2)

    assert worker.submit(_alert()) is True
    assert worker.submit(_alert()) is True
    assert worker.submit(_alert()) is False  # dropped rather than unbounded growth
    assert worker.get_stats()["dropped"] == 1


def test_worker_runs_on_a_background_thread() -> None:
    service = _RecordingService()
    worker = EnrichmentWorker(service, poll_seconds=0.01)
    worker.start()
    try:
        worker.submit(_alert())
        for _ in range(200):
            if service.seen:
                break
            time.sleep(0.01)
        assert service.seen
    finally:
        worker.stop()
    assert worker.is_running is False


def test_worker_survives_an_enrichment_failure() -> None:
    class Exploding(ThreatIntelService):
        def enrich_alert(self, alert: Alert) -> None:
            raise RuntimeError("provider layer exploded")

    worker = EnrichmentWorker(Exploding(providers=[]))
    worker.submit(_alert())
    assert worker.drain() == 1  # must not propagate


def test_enrichment_never_blocks_the_alert_pipeline() -> None:
    """Alerts are persisted and returned before any enrichment happens."""
    service = _RecordingService()
    worker = EnrichmentWorker(service)
    alerts = AlertService(enrichment_sink=worker.submit)

    alert = alerts.handle_detection(
        DetectionAlert(
            detector_name="TcpPortScanDetector",
            severity=Severity.HIGH,
            description="scan",
            src_ip=PUBLIC_IP,
        )
    )

    assert alert is not None
    assert alerts.get_alert(alert.alert_id) is alert  # persisted already
    assert alert.threat_intel is None  # not yet enriched
    assert worker.queue_depth == 1  # queued for later

    worker.drain()
    assert service.seen == [alert]
