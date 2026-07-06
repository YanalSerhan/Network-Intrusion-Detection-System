"""
Detection service orchestrating the rule engine and heuristic detectors.

Data Setup:  Detector registry and rule engine injected via constructor.
Data Input:  Parsed packet objects from the parser service.
Data Output: Alert objects emitted to the alert service.
"""

from pathlib import Path
from typing import Any, Callable

from network_defender.detectors import DetectorRegistry
from network_defender.detectors.models import DetectionAlert
from network_defender.parser.models import ParsedPacket

from ..shared.base import BaseService


class DetectionService(BaseService):
    """
    Orchestrates the rule engine and heuristic detectors.
    """

    def __init__(self, config_dir: str | Path, alert_callback: Callable[[DetectionAlert], None] | None = None) -> None:
        super().__init__(service_name="DetectionService")
        self.config_dir = Path(config_dir)
        self.registry = DetectorRegistry(str(self.config_dir))
        self.alert_callback = alert_callback

    def _do_start(self) -> None:
        self.logger.info("DetectionService starting: loading detectors...")
        self.registry.load_detectors()
        self.logger.info(f"DetectionService started. Loaded {len(self.registry.detectors)} heuristic detectors.")

    def _do_stop(self) -> None:
        self.logger.info("DetectionService stopped.")

    def _do_health_check(self) -> dict[str, Any]:
        return {
            "detectors_loaded": len(self.registry.detectors),
            "status": "ok" if self.registry.detectors else "degraded"
        }

    def process_packet(self, packet: ParsedPacket) -> None:
        """
        Process a single packet through all detectors.
        """
        for detector in self.registry.detectors:
            try:
                detector.ingest(packet)
            except Exception as e:
                self.logger.error(f"Detector {detector.name} failed during ingest: {e}")

    def evaluate_detectors(self) -> list[DetectionAlert]:
        """
        Force evaluation of all detectors (typically called on a timer/loop).
        """
        all_alerts = []
        for detector in self.registry.detectors:
            try:
                alerts = detector.evaluate()
                if alerts:
                    all_alerts.extend(alerts)
                    if self.alert_callback:
                        for alert in alerts:
                            self.alert_callback(alert)
            except Exception as e:
                self.logger.error(f"Detector {detector.name} failed during evaluation: {e}")
        return all_alerts
