"""
SDK lifecycle and health.

Data Setup:  Expects the composing class to own every service attribute.
Data Input:  start/stop calls from an entry point.
Data Output: Running services, and a unified health payload.

Three start modes, because three processes need different amounts of the
system. `start()` runs everything including live capture, for the sensor.
`start_readonly()` brings up only what is needed to read and enrich stored
data, so the API needs no raw-socket privileges and can restart without
interrupting capture. `start_offline()` runs the whole detection pipeline with
no sniffer, which is what replaying a capture file needs and what makes the
detectors runnable without root.

`stop()` unwinds all three: every service's stop is safe to call on one that
was never started.
"""

from ..observability import setup_logging
from ..services.alerts.service import AlertService
from ..services.capture import CaptureService
from ..services.database import DatabaseService
from ..services.detection import DetectionService
from ..services.maintenance import MaintenanceService
from ..services.parser import PacketParser
from ..services.statistics_sampler import StatisticsSampler
from ..services.threat_intel.service import ThreatIntelService
from ..services.threat_intel.worker import EnrichmentWorker
from ..shared.base import LoggableMixin

#: Components the API needs; capture and detection run in the sensor container.
READONLY_REQUIRED = ("database", "alerting")


class LifecycleMixin(LoggableMixin):
    """Start, stop and health-check surface of the SDK."""

    # Owned by the composing SDK; declared so this mixin type-checks alone.
    _database_service: DatabaseService
    _alert_service: AlertService
    _threat_intel_service: ThreatIntelService
    _enrichment_worker: EnrichmentWorker
    _parser_service: PacketParser
    _detection_service: DetectionService
    _capture_service: CaptureService
    _statistics_sampler: StatisticsSampler
    _maintenance_service: MaintenanceService

    def start(self) -> None:
        """
        Start every domain service, including live packet capture.

        Capture starts last: downstream services must be ready before the first
        packet arrives, or early traffic hits an unloaded detector registry and
        is silently lost. Maintenance starts after capture so the first
        throughput sample has a baseline to measure against.
        """
        self._start_pipeline("network-defender-sensor")
        self._capture_service.start()
        self._start_background()

    def start_offline(self) -> None:
        """
        Start everything except the live sniffer, for replaying a capture file.

        `start()` opens a raw socket, which needs CAP_NET_RAW and an interface
        that exists. Replaying a .pcap needs neither — the replay path feeds
        the same packet callback from a file — but until this existed the only
        way to reach it was to start live capture first and then not use it.
        That made the documented way to try a detector impossible to run
        without root, and impossible in CI.
        """
        self._start_pipeline("network-defender-replay")
        self._start_background()

    def _start_pipeline(self, service_name: str) -> None:
        """Start every service a packet passes through, in dependency order."""
        setup_logging(service=service_name)
        self.logger.info("NetworkDefenderSDK starting services.")
        self._database_service.start()
        self._alert_service.start()
        self._threat_intel_service.start()
        self._enrichment_worker.start()
        self._parser_service.start()
        self._detection_service.start()
        self._sync_rule_snapshot()

    def _start_background(self) -> None:
        """Start the sampler and maintenance timers, once traffic can arrive."""
        self._statistics_sampler.reset()
        self._maintenance_service.start()
        self.logger.info("NetworkDefenderSDK ready.")

    def stop(self) -> None:
        """Stop all domain services in reverse order."""
        self.logger.info("NetworkDefenderSDK stopping all services.")
        self._maintenance_service.stop()
        self._capture_service.stop()
        self._detection_service.stop()
        self._parser_service.stop()
        self._enrichment_worker.stop()
        self._threat_intel_service.stop()
        self._alert_service.stop()
        self._database_service.stop()
        self.logger.info("NetworkDefenderSDK shut down.")

    def start_readonly(self) -> None:
        """
        Start only the services needed to read and enrich stored data.

        Used by the REST API. Capture and detection are deliberately left
        stopped: the API must not open a network interface.
        """
        self.logger.info("NetworkDefenderSDK starting in read-only mode.")
        self._database_service.start()
        self._alert_service.start()
        self._threat_intel_service.start()

    def stop_readonly(self) -> None:
        """Stop the services started by start_readonly()."""
        self.logger.info("NetworkDefenderSDK stopping read-only services.")
        self._threat_intel_service.stop()
        self._alert_service.stop()
        self._database_service.stop()

    def _sync_rule_snapshot(self) -> None:
        """
        Mirror the loaded rule set into the database.

        Lets the API list active rules without reading the filesystem.
        Best-effort: a snapshot failure must not stop the sensor.
        """
        engine = self._detection_service.rule_engine
        if engine is None:
            return
        try:
            self._database_service.rules.sync(engine.loader.registry.get_all_enabled_rules())
        except Exception as exc:  # noqa: BLE001 - snapshot is not load-bearing
            self.logger.error("Failed to snapshot rules: %s", exc)
