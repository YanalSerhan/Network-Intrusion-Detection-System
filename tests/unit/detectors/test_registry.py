"""
Tests for the detector plugin loader's failure paths.

The registry loads detectors by importing a package and reflecting over its
classes, so everything it deals with can be wrong: a missing config file, an
unparseable one, a detector whose config is not a config, a config whose
values fail validation. None of those may take the sensor down — a single
broken plugin should cost its own detector and nothing else — so each one is
pinned here.
"""

import json
from pathlib import Path
from typing import Any

import pytest

from network_defender.detectors.base import BaseDetector
from network_defender.detectors.models import DetectionAlert, DetectorConfig
from network_defender.detectors.registry import DetectorRegistry
from network_defender.parser.models import ParsedPacket


class WorkingConfig(DetectorConfig):
    """Config with one tunable, to prove overrides are applied."""

    threshold: int = 5


class WorkingDetector(BaseDetector[WorkingConfig]):
    """A detector that loads cleanly."""

    def __init__(self, config: WorkingConfig) -> None:
        super().__init__(config)

    @property
    def name(self) -> str:
        return "WorkingDetector"

    def ingest(self, packet: ParsedPacket) -> None:
        """Accept and ignore."""

    def evaluate(self) -> list[DetectionAlert]:
        """Never alert."""
        return []


class UntypedDetector(WorkingDetector):
    """A detector whose config parameter carries no annotation."""

    def __init__(self, config) -> None:  # type: ignore[no-untyped-def] # noqa: ANN001
        super().__init__(config)


class NotAConfig:
    """Stands in for an annotation that is not a DetectorConfig subclass."""


class WrongConfigDetector(WorkingDetector):
    """A detector annotated with something that is not a config."""

    def __init__(self, config: NotAConfig) -> None:  # type: ignore[override]
        super().__init__(config)  # type: ignore[arg-type]


class ExplodingDetector(WorkingDetector):
    """A detector whose constructor fails, as a broken plugin's would."""

    def __init__(self, config: WorkingConfig) -> None:
        raise RuntimeError("plugin is broken")


@pytest.fixture()
def registry(tmp_path: Path) -> DetectorRegistry:
    """A registry over a config directory holding one detector's settings."""
    (tmp_path / "detectors.json").write_text(
        json.dumps({"WorkingDetector": {"enabled": True, "threshold": 42}})
    )
    return DetectorRegistry(str(tmp_path))


def test_configured_values_reach_the_detector(registry: DetectorRegistry) -> None:
    registry._register_detector_class(WorkingDetector)

    assert len(registry.detectors) == 1
    config: Any = registry.detectors[0].config
    assert config.threshold == 42


def test_a_detector_with_no_typed_config_is_skipped(registry: DetectorRegistry) -> None:
    registry._register_detector_class(UntypedDetector)
    assert registry.detectors == []


def test_a_config_that_is_not_a_detector_config_is_skipped(registry: DetectorRegistry) -> None:
    registry._register_detector_class(WrongConfigDetector)
    assert registry.detectors == []


def test_a_config_that_fails_validation_is_skipped(tmp_path: Path) -> None:
    (tmp_path / "detectors.json").write_text(
        json.dumps({"WorkingDetector": {"threshold": "not-a-number"}})
    )
    registry = DetectorRegistry(str(tmp_path))

    registry._register_detector_class(WorkingDetector)
    assert registry.detectors == []


def test_a_disabled_detector_is_not_registered(tmp_path: Path) -> None:
    (tmp_path / "detectors.json").write_text(json.dumps({"WorkingDetector": {"enabled": False}}))
    registry = DetectorRegistry(str(tmp_path))

    registry._register_detector_class(WorkingDetector)
    assert registry.detectors == []


def test_a_detector_that_fails_to_construct_is_skipped(registry: DetectorRegistry) -> None:
    registry._register_detector_class(ExplodingDetector)
    assert registry.detectors == []
