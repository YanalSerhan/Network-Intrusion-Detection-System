"""
The unified health payload the API serves.

Data Setup:  Expects the composing class to own every service attribute.
Data Input:  None.
Data Output: Overall status plus per-component sub-status.

Split from `lifecycle` because it answers a different question. Lifecycle
decides *which* services a process runs; this reports on whichever are
running, and the two change for unrelated reasons.
"""

from typing import Any

from ..constants import PROJECT_VERSION
from ..services.alerts.service import AlertService
from ..services.capture import CaptureService
from ..services.database import DatabaseService
from ..services.detection import DetectionService
from ..services.maintenance import MaintenanceService
from ..services.parser import PacketParser
from ..services.threat_intel.service import ThreatIntelService


class HealthMixin:
    """Health-reporting surface of the SDK."""

    _database_service: DatabaseService
    _alert_service: AlertService
    _threat_intel_service: ThreatIntelService
    _parser_service: PacketParser
    _detection_service: DetectionService
    _capture_service: CaptureService
    _maintenance_service: MaintenanceService

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
