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
from network_defender.rules.models import Rule

from ..shared.base import BaseService
from ..shared.config_models import DetectionConfig
from ..shared.paths import resolve_project_path
from .evaluation_loop import PeriodicEvaluator

DetectionCallback = Callable[[DetectionAlert], None]
RuleCallback = Callable[[Rule, ParsedPacket], None]


class DetectionService(BaseService):
    """
    Orchestrates the rule engine and heuristic detectors.

    Every packet is evaluated against the YAML signature rules immediately and
    ingested by every enabled heuristic detector. Stateful detectors are
    evaluated on a timer so their windows are flushed and alerts are emitted
    without an external scheduler.
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
        self.rule_engine = RuleEngine(str(self.rules_dir)) if self.rules_dir else None
        self.alert_callback = alert_callback
        self.rule_callback = rule_callback
        self._evaluator = PeriodicEvaluator(
            self.config.evaluation_interval_seconds, self.evaluate_detectors
        )
        self._packets_processed = 0

    def _do_start(self) -> None:
        """Load detectors and rules, then start the periodic evaluation loop."""
        self.registry.load_detectors()
        if self.rule_engine is not None:
            self.rule_engine.start()
        self._evaluator.start()
        self.logger.info("DetectionService started: %d detectors.", len(self.registry.detectors))

    def _do_stop(self) -> None:
        """Stop the evaluation loop and flush any pending detector state."""
        self._evaluator.stop()
        self._evaluator.run_once()
        if self.rule_engine is not None:
            self.rule_engine.stop()
        self.logger.info("DetectionService stopped.")

    def _do_health_check(self) -> dict[str, Any]:
        """Report loaded detector/rule counts and throughput for /health."""
        engine = self.rule_engine
        rules_loaded = len(engine.loader.registry.get_all_enabled_rules()) if engine else 0
        return {
            "detectors_loaded": len(self.registry.detectors),
            "rules_loaded": rules_loaded,
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
        self._evaluate_rules(packet)
        for detector in self.registry.detectors:
            try:
                detector.ingest(packet)
            except Exception as exc:  # noqa: BLE001 - one bad detector must not stall the pipeline
                self.logger.error("Detector %s failed during ingest: %s", detector.name, exc)

    def _evaluate_rules(self, packet: ParsedPacket) -> None:
        """Evaluate YAML signature rules and dispatch any matches."""
        if self.rule_engine is None or not self.config.evaluate_rules:
            return
        try:
            matches = self.rule_engine.evaluate(packet)
        except Exception as exc:  # noqa: BLE001 - a bad rule must not stall the pipeline
            self.logger.error("Rule evaluation failed: %s", exc)
            return
        if self.rule_callback is None:
            return
        for rule in matches:
            self.rule_callback(rule, packet)

    def evaluate_detectors(self) -> list[DetectionAlert]:
        """
        Evaluate every detector, flushing its window and emitting its alerts.

        Returns:
            All alerts produced by this evaluation cycle.
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
                    self.alert_callback(alert)
        return all_alerts
