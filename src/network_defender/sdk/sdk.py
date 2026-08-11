"""
NetworkDefenderSDK — the single entry point for all business logic.

ARCHITECTURE RULE:
  All external consumers (CLI, REST API, dashboard WebSocket handlers)
  MUST call methods on NetworkDefenderSDK. No business logic belongs
  in presentation or transport layers.

Data Setup:  Constructed once at application startup with validated configs.
Data Input:  High-level commands from consumers (start, stop, query alerts…).
Data Output: Structured results (health dicts, alert lists, status objects).
"""

from pathlib import Path
from typing import Any

from scapy.packet import Packet  # type: ignore[import-untyped]

from ..capture.interface_discovery import list_interfaces
from ..capture.models import CaptureStatus
from ..observability import setup_logging
from ..parser.models import ParsedPacket
from ..services.alerts import AlertService
from ..services.capture import CaptureService
from ..services.database import DatabaseService
from ..services.detection import DetectionService
from ..services.maintenance import MaintenanceService
from ..services.parser import PacketParser
from ..services.statistics_sampler import StatisticsSampler
from ..services.threat_intel.factory import build_service
from ..services.threat_intel.tiered_cache import TieredThreatIntelCache
from ..services.threat_intel.worker import EnrichmentWorker
from ..shared.base import LoggableMixin
from ..shared.config import load_app_config, load_rate_limit_config
from ..shared.config_models import AppConfig
from ..shared.gatekeeper import ApiGatekeeper
from ..shared.rate_limit_models import RateLimitConfig
from .alert_operations import AlertOperationsMixin
from .database_operations import DatabaseOperationsMixin
from .maintenance_operations import MaintenanceOperationsMixin
from .pipeline import PipelineMixin
from .rule_operations import RuleOperationsMixin
from .threat_intel_operations import ThreatIntelOperationsMixin


class NetworkDefenderSDK(
    AlertOperationsMixin,
    ThreatIntelOperationsMixin,
    DatabaseOperationsMixin,
    MaintenanceOperationsMixin,
    RuleOperationsMixin,
    PipelineMixin,
    LoggableMixin,
):
    """
    Facade over all Network Defender domain services.

    Responsibilities:
      - Assemble and own all service instances.
      - Expose high-level, consumer-friendly methods.
      - Ensure every outbound API call routes through the gatekeeper.
      - Provide a unified health-check surface for the /health endpoint.

    Usage:
        sdk = NetworkDefenderSDK.create()
        sdk.start()
        health = sdk.get_health()
        sdk.stop()
    """

    def __init__(
        self,
        app_config: AppConfig,
        rate_limit_config: RateLimitConfig,
    ) -> None:
        """
        Initialise the SDK with validated configuration.

        Args:
            app_config:        Validated application configuration.
            rate_limit_config: Validated rate-limit configuration for all external services.
        """
        self._app_config = app_config
        self._rate_limit_config = rate_limit_config

        # Build service instances with injected configs (no hardcoded values).
        # The database is built first: every other service either persists
        # through it or reads a repository from it.
        self._database_service = DatabaseService(config=app_config.database)
        self._capture_service = CaptureService(config=app_config.capture)
        self._parser_service = PacketParser()
        # The alert service comes before detection so detector alerts can be
        # routed straight into the alert pipeline via the detection callback.
        self._alert_service = AlertService(
            repository=self._database_service.alerts,
            enrichment_sink=self._submit_for_enrichment,
        )
        self._detection_service = DetectionService(
            config_dir=app_config.config_dir,
            rules_dir=app_config.rules_dir,
            alert_callback=self._on_detection,
            rule_callback=self._on_rule_match,
            config=app_config.detection,
        )

        # Build per-service gatekeepers from config.
        self._gatekeepers: dict[str, ApiGatekeeper] = {
            name: ApiGatekeeper(service_name=name, config=svc_cfg)
            for name, svc_cfg in rate_limit_config.services.items()
        }

        # Threat intel enrichment runs off the alert path on its own worker.
        # Its cache is backed by the database so a 24h reputation TTL survives
        # a restart instead of being re-fetched against a 10 req/min budget.
        self._threat_intel_service = build_service(self._gatekeepers)
        self._threat_intel_service.cache = TieredThreatIntelCache(  # type: ignore[assignment]
            durable=self._database_service.threat_intel_cache
        )
        self._enrichment_worker = EnrichmentWorker(
            service=self._threat_intel_service,
            on_enriched=self._save_enriched_alert,
        )

        # Derives packets/sec from consecutive cumulative counter readings.
        self._statistics_sampler = StatisticsSampler()

        # Nothing called these before: the throughput chart stayed empty and
        # retention never ran, so the database grew without bound.
        self._maintenance_service = MaintenanceService(
            record_snapshot=self.record_statistics_snapshot,
            prune=self.prune_old_data,
            config=app_config.maintenance,
        )

        # Connect capture -> parser -> detection -> alerting.
        self._wire_pipeline()

    # ------------------------------------------------------------------
    # Factory
    # ------------------------------------------------------------------

    @classmethod
    def create(cls) -> "NetworkDefenderSDK":
        """
        Convenience factory: load configs from disk and construct the SDK.

        Returns:
            A fully initialised NetworkDefenderSDK instance.
        """
        app_config = load_app_config()
        rate_limit_config = load_rate_limit_config()
        return cls(app_config=app_config, rate_limit_config=rate_limit_config)

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def start(self) -> None:
        """
        Start all domain services in dependency order.

        Capture starts last: the downstream services must be ready before the
        first packet arrives, otherwise early traffic hits an unloaded
        detector registry and is silently lost.
        """
        setup_logging(service="network-defender-sensor")
        self.logger.info("NetworkDefenderSDK starting all services.")
        self._database_service.start()
        self._alert_service.start()
        self._threat_intel_service.start()
        self._enrichment_worker.start()
        self._parser_service.start()
        self._detection_service.start()
        self._sync_rule_snapshot()
        self._capture_service.start()
        # Started after capture so the first throughput sample has a baseline.
        self._statistics_sampler.reset()
        self._maintenance_service.start()
        self.logger.info("NetworkDefenderSDK ready.")

    def _sync_rule_snapshot(self) -> None:
        """
        Mirror the loaded rule set into the database.

        Lets the API and dashboard list the active rules without reading the
        filesystem. Best-effort: a snapshot failure must not stop the sensor.
        """
        engine = self._detection_service.rule_engine
        if engine is None:
            return
        try:
            self._database_service.rules.sync(engine.loader.registry.get_all_enabled_rules())
        except Exception as exc:  # noqa: BLE001 - snapshot is not load-bearing
            self.logger.error("Failed to snapshot rules: %s", exc)

    def start_readonly(self) -> None:
        """
        Start only the services needed to read and enrich stored data.

        Used by the REST API, which per PLAN.md §4 runs in its own container
        alongside the sensor. Capture and detection are deliberately left
        stopped: the API must not open a network interface, so it needs no
        raw-socket privileges and can restart without interrupting capture.
        """
        self.logger.info("NetworkDefenderSDK starting in read-only mode.")
        self._database_service.start()
        self._alert_service.start()
        self._threat_intel_service.start()
        self.logger.info("NetworkDefenderSDK ready (read-only).")

    def stop_readonly(self) -> None:
        """Stop the services started by start_readonly()."""
        self.logger.info("NetworkDefenderSDK stopping read-only services.")
        self._threat_intel_service.stop()
        self._alert_service.stop()
        self._database_service.stop()

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

    # ------------------------------------------------------------------
    # Health
    # ------------------------------------------------------------------

    def get_health(self) -> dict[str, Any]:
        """
        Return a unified health-check payload suitable for /health endpoint.

        Returns:
            Dict with overall status and per-service sub-statuses.
        """
        components = {
            "capture": self._capture_service.health_check(),
            "parser": self._parser_service.health_check(),
            "detection": self._detection_service.health_check(),
            "alerting": self._alert_service.health_check(),
            "threat_intel": self._threat_intel_service.health_check(),
            "database": self._database_service.health_check(),
            "maintenance": self._maintenance_service.health_check(),
        }
        all_ok = all(c.get("running", False) for c in components.values())
        return {
            "status": "ok" if all_ok else "degraded",
            "components": components,
        }

    # ------------------------------------------------------------------
    # Gatekeeper access (for Threat Intel service layer)
    # ------------------------------------------------------------------

    def get_gatekeeper(self, service_name: str) -> ApiGatekeeper:
        """
        Retrieve the gatekeeper for a named external service.

        Args:
            service_name: Must match a key in config/rate_limits.json.

        Returns:
            The ApiGatekeeper instance for that service.

        Raises:
            KeyError: If the service is not configured.
        """
        if service_name not in self._gatekeepers:
            raise KeyError(
                f"No gatekeeper configured for service '{service_name}'. "
                f"Available: {list(self._gatekeepers.keys())}"
            )
        return self._gatekeepers[service_name]

    # ------------------------------------------------------------------
    # Capture operations
    # ------------------------------------------------------------------

    def start_capture(self) -> None:
        """
        Start live packet capture on the configured network interface.

        Delegates to CaptureService.start() via the BaseService template.
        """
        self._capture_service.start()

    def stop_capture(self) -> None:
        """Stop the active live capture session."""
        self._capture_service.stop()

    def start_capture_from_pcap(self, path: str | Path) -> None:
        """
        Replay packets from a PCAP file through the full filter/detection pipeline.

        Args:
            path: Absolute or relative path to the .pcap file.
        """
        self._capture_service.start_pcap_replay(path)

    def save_capture_to_pcap(self, path: str | Path) -> None:
        """
        Save all packets captured in the current session to a PCAP file.

        Args:
            path: Destination file path.
        """
        self._capture_service.save_to_pcap(path)

    def get_capture_status(self) -> CaptureStatus:
        """
        Return a snapshot of the capture service's current state.

        Returns:
            CaptureStatus Pydantic model with counters and config summary.
        """
        return self._capture_service.get_status()

    def list_interfaces(self) -> list[str]:
        """
        Return the sorted list of all network interfaces visible to Scapy.

        Returns:
            List of interface name strings (e.g. ['eth0', 'lo', 'wlan0']).
        """
        return list_interfaces()

    # ------------------------------------------------------------------
    # Parser operations
    # ------------------------------------------------------------------

    def parse_packet(self, pkt: Packet) -> ParsedPacket:
        """
        Parse a raw Scapy packet into a normalised ParsedPacket model.

        Args:
            pkt: A Scapy Packet object captured by CaptureService.

        Returns:
            ParsedPacket with all available protocol fields populated.

        Raises:
            ValueError: If pkt is None or not a valid Packet instance.
        """
        return self._parser_service.parse(pkt)

    def parse_packet_safe(self, pkt: Packet) -> ParsedPacket | None:
        """
        Parse a packet without raising — returns None on any failure.

        Intended for use in high-throughput capture callbacks where a single
        malformed packet must not interrupt the processing pipeline.

        Args:
            pkt: A Scapy Packet object.

        Returns:
            ParsedPacket on success; None if parsing fails for any reason.
        """
        return self._parser_service.parse_safe(pkt)
