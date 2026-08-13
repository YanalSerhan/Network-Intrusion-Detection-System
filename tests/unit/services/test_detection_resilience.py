"""
Tests that one broken detector or rule cannot stall the pipeline.

Detectors and rules are plugins: a third-party detector, or a rule someone
edited on a live sensor, can raise on any packet. If that propagated, one bad
plugin would stop the sensor seeing traffic at all — so every call into a
plugin is isolated, and this is where that isolation is pinned.
"""

from pathlib import Path
from unittest.mock import MagicMock

import pytest

from network_defender.detectors.models import DetectionAlert
from network_defender.services.detection import DetectionService
from network_defender.shared.config_models import DetectionConfig
from network_defender.shared.paths import PROJECT_ROOT
from tests.fixtures.builders import make_packet


class _ExplodingDetector:
    """A plugin that fails at both points the service calls into it."""

    name = "ExplodingDetector"

    def ingest(self, packet: object) -> None:
        raise RuntimeError("ingest exploded")

    def evaluate(self) -> list[DetectionAlert]:
        raise RuntimeError("evaluate exploded")


@pytest.fixture()
def service() -> DetectionService:
    """A detection service with the shipped detectors and no rule engine."""
    instance = DetectionService(config_dir=PROJECT_ROOT / "config")
    instance.registry.load_detectors()
    return instance


def test_a_detector_that_raises_on_ingest_does_not_stop_the_others(
    service: DetectionService,
) -> None:
    service.registry.detectors.insert(0, _ExplodingDetector())  # type: ignore[arg-type]

    for _ in range(20):
        service.process_packet(make_packet(dst_port=4444))

    assert service.health_check()["packets_processed"] == 20
    assert any(a.detector_name == "SuspiciousPortDetector" for a in service.evaluate_detectors())


def test_a_detector_that_raises_on_evaluate_is_skipped(service: DetectionService) -> None:
    service.registry.detectors.insert(0, _ExplodingDetector())  # type: ignore[arg-type]
    service.process_packet(make_packet(dst_port=4444))

    alerts = service.evaluate_detectors()

    assert [a.detector_name for a in alerts] == ["SuspiciousPortDetector"]


def test_a_failing_rule_engine_does_not_stop_detection(tmp_path: Path) -> None:
    """A rule that raises must cost the rule, not the packet."""
    service = DetectionService(config_dir=PROJECT_ROOT / "config", rules_dir=tmp_path)
    service.registry.load_detectors()
    assert service.rule_engine is not None
    service.rule_engine.evaluate = MagicMock(side_effect=RuntimeError("bad rule"))  # type: ignore[method-assign]

    service.process_packet(make_packet())

    assert service.health_check()["packets_processed"] == 1


def test_rule_evaluation_is_skipped_when_disabled(tmp_path: Path) -> None:
    """The config switch has to actually stop the work, not just the alerts."""
    service = DetectionService(
        config_dir=PROJECT_ROOT / "config",
        rules_dir=tmp_path,
        config=DetectionConfig(evaluate_rules=False),
    )
    assert service.rule_engine is not None
    service.rule_engine.evaluate = MagicMock()  # type: ignore[method-assign]

    service.process_packet(make_packet())

    service.rule_engine.evaluate.assert_not_called()


def test_matches_are_dropped_when_no_rule_callback_is_wired(tmp_path: Path) -> None:
    """Standalone use of the service must not require a callback."""
    rule_file = tmp_path / "rule.yaml"
    rule_file.write_text(
        "name: Any TCP\nseverity: low\nenabled: true\n"
        "conditions:\n  - field: protocol\n    operator: equals\n    value: tcp\n"
    )
    service = DetectionService(config_dir=PROJECT_ROOT / "config", rules_dir=tmp_path)
    service.start()
    try:
        service.process_packet(make_packet())
        assert service.health_check()["packets_processed"] == 1
    finally:
        service.stop()
