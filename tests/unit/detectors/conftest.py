"""Fixtures shared by the detector registry suites."""

import json
from pathlib import Path

import pytest

from network_defender.detectors.registry import DetectorRegistry


@pytest.fixture()
def registry(tmp_path: Path) -> DetectorRegistry:
    """A registry over a config directory holding one detector's settings."""
    (tmp_path / "detectors.json").write_text(
        json.dumps({"WorkingDetector": {"enabled": True, "threshold": 42}})
    )
    return DetectorRegistry(str(tmp_path))
