"""
SDK lifecycle and health.

Data Setup:  Expects the composing class to own every service attribute.
Data Input:  start/stop calls from an entry point.
Data Output: Running services, and a unified health payload.

Two start modes, because the sensor and the API are separate containers
(PLAN.md §4). `start()` runs everything including capture; `start_readonly()`
brings up only what is needed to read and enrich stored data, so the API needs
no raw-socket privileges and can restart without interrupting capture.
"""

from typing import Any

from ..constants import PROJECT_VERSION
from ..observability import setup_logging
from ..shared.base import LoggableMixin

#: Components the API needs; capture and detection run in the sensor container.
READONLY_REQUIRED = ("database", "alerting")


class LifecycleMixin(LoggableMixin):
    """Start, stop and health-check surface of the SDK."""

    def start(self) -> None:
        """
        Start all domain services in dependency order.

        Capture starts last: downstream services must be ready before the first
        packet arrives, or early traffic hits an unloaded detector registry and
        is silently lost. Maintenance starts after capture so the first
        throughput sample has a baseline to measure against.
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

    def get_health(self) -> dict[str, Any]:
        """
        Return a unified health payload for the /health endpoint.

        Returns:
            Overall status plus per-component sub-status.
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
        all_ok = all(component.get("running", False) for component in components.values())
        return {
            "status": "ok" if all_ok else "degraded",
            "version": PROJECT_VERSION,
            "components": components,
        }

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
