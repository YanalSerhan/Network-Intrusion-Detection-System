"""
Detection service orchestrating the rule engine and heuristic detectors.

Data Setup:  Config directory (detectors.json), rules directory (YAML rules)
             and alert callbacks injected via constructor. Both directories are
             resolved against the project root, not the current working
             directory, so the service behaves identically wherever it is run.
Data Input:  Parsed packet objects from the parser service.
Data Output: DetectionAlerts from heuristics and Rule matches from signatures,
             both delivered to the alert service via callbacks.
"""

from collections.abc import Callable
from pathlib import Path
from typing import Any

from network_defender.detectors import DetectorRegistry
from network_defender.detectors.models import DetectionAlert
from network_defender.parser.models import ParsedPacket
from network_defender.rules.engine import RuleEngine
from network_defender.services.detection_dispatch import dispatch_detector_alert
from network_defender.services.detection_rules import RuleCallback, RuleEvaluation
from network_defender.services.evaluation_loop import PeriodicEvaluator
from network_defender.shared.base import BaseService
from network_defender.shared.config_models import DetectionConfig
from network_defender.shared.paths import resolve_project_path

DetectionCallback = Callable[[DetectionAlert], None]


class DetectionService(BaseService):
    """
    Orchestrates the rule engine and heuristic detectors.

    Every packet is evaluated against the YAML signature rules immediately and
    ingested by every enabled heuristic detector. Stateful detectors are asked
    on a timer, so alerts surface without an external scheduler. Asking is not
    flushing: each detector's window slides over capture time and expires by
    age, so a quiet evaluation is how one re-arms after an episode ends.
    """

    def __init__(
        self,
        config_dir: str | Path,
        rules_dir: str | Path | None = None,
        alert_callback: DetectionCallback | None = None,
        rule_callback: RuleCallback | None = None,
        config: DetectionConfig | None = None,
    ) -> None:
        """
        Initialise the detection service.

        Args:
            config_dir:     Directory holding detectors.json (per-detector config).
            rules_dir:      Directory holding YAML signature rules. Rule
                            evaluation is disabled when omitted.
            alert_callback: Invoked for each heuristic DetectionAlert.
            rule_callback:  Invoked for each (Rule, ParsedPacket) signature match.
            config:         Detection tunables; defaults are used when omitted.
        """
        super().__init__(service_name="DetectionService")
        self.config = config or DetectionConfig()
        self.config_dir = resolve_project_path(config_dir)
        self.rules_dir = resolve_project_path(rules_dir) if rules_dir is not None else None
        self.registry = DetectorRegistry(str(self.config_dir))
        self.rules = (
            RuleEvaluation(self.rules_dir, self.logger, rule_callback)
            if self.rules_dir
            else None
        )
        self.alert_callback = alert_callback
        self._evaluator = PeriodicEvaluator(
            self.config.evaluation_interval_seconds, self.evaluate_detectors
        )
        self._packets_processed = 0

    @property
    def rule_engine(self) -> RuleEngine | None:
        """
        The signature engine, or None when the service runs detectors alone.

        The SDK's rule operations reload and query rules through this, which
        is why the split into RuleEvaluation stayed internal.
        """
        return self.rules.engine if self.rules is not None else None

    def _do_start(self) -> None:
        """Load detectors and rules, then start the periodic evaluation loop."""
        self.registry.load_detectors()
        if self.rules is not None:
            self.rules.start()
        self._evaluator.start()
        self.logger.info("DetectionService started: %d detectors.", len(self.registry.detectors))

    def _do_stop(self) -> None:
        """Stop the evaluation loop, asking once more for anything outstanding."""
        self._evaluator.stop()
        self._evaluator.run_once()
        if self.rules is not None:
            self.rules.stop()
        self.logger.info("DetectionService stopped.")

    def _do_health_check(self) -> dict[str, Any]:
        """Report loaded detector/rule counts and throughput for /health."""
        return {
            "detectors_loaded": len(self.registry.detectors),
            "rules_loaded": self.rules.rules_loaded if self.rules else 0,
            "packets_processed": self._packets_processed,
            "evaluation_loop_running": self._evaluator.is_running,
            "status": "ok" if self.registry.detectors else "degraded",
        }

    def process_packet(self, packet: ParsedPacket) -> None:
        """
        Run a single packet through the signature rules and every detector.

        Args:
            packet: The normalised packet emitted by the parser service.
        """
        self._packets_processed += 1
        if self.rules is not None and self.config.evaluate_rules:
            self.rules.evaluate(packet)
        for detector in self.registry.detectors:
            try:
                detector.ingest(packet)
            except Exception as exc:  # noqa: BLE001 - one bad detector must not stall the pipeline
                self.logger.error("Detector %s failed during ingest: %s", detector.name, exc)

    def evaluate_detectors(self) -> list[DetectionAlert]:
        """
        Ask every detector whether its window is over threshold.

        Returns:
            All alerts produced by this evaluation cycle. Usually none: a
            detector reports an episode once and stays quiet until it ends.
        """
        all_alerts: list[DetectionAlert] = []
        for detector in self.registry.detectors:
            try:
                alerts = detector.evaluate()
            except Exception as exc:  # noqa: BLE001 - isolate detector failures
                self.logger.error("Detector %s failed during evaluation: %s", detector.name, exc)
                continue
            all_alerts.extend(alerts)
            if self.alert_callback is not None:
                for alert in alerts:
                    dispatch_detector_alert(alert, self.alert_callback)
        return all_alerts
