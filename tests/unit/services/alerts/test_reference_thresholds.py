"""
Tests that confidence is scored against the configured threshold.

The reference magnitude used to be a second copy of config/detectors.json
kept in source, and the copies had drifted: exfiltration scored against 100 MB
while the detector fired at 50 MB, and lateral movement scored against 10
destinations while the detector fired at 20. Nothing failed, because a
plausible confidence score is indistinguishable from a correct one.
"""

import json
from pathlib import Path
from typing import Any

import pytest

from network_defender.constants import CONFIG_FILE_DETECTORS, Severity
from network_defender.services.alerts import reference_thresholds
from network_defender.services.alerts.confidence import score_alert
from network_defender.services.alerts.reference_thresholds import (
    DETECTOR_EVIDENCE_KEYS,
    reference_magnitude,
    reset_cache,
)
from network_defender.shared.paths import CONFIG_DIR


@pytest.fixture(autouse=True)
def _clear_cache() -> Any:
    """The module caches the file; every test here starts from a cold read."""
    reset_cache()
    yield
    reset_cache()


def _shipped_config() -> dict[str, Any]:
    """Return the detector configuration the project ships."""
    return dict(json.loads((CONFIG_DIR / CONFIG_FILE_DETECTORS).read_text()))


@pytest.mark.parametrize("detector", sorted(DETECTOR_EVIDENCE_KEYS))
def test_every_reference_comes_from_the_shipped_configuration(detector: str) -> None:
    """No detector may score against a number that exists only in source."""
    _, config_key = DETECTOR_EVIDENCE_KEYS[detector]
    configured = _shipped_config().get(detector, {}).get(config_key)

    assert configured is not None, (
        f"{detector} scores against '{config_key}', which config/detectors.json "
        f"does not define — the reference would silently fall back to none."
    )
    assert reference_magnitude(detector) == float(configured)


def test_changing_the_configured_threshold_changes_the_score(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Retuning a detector must retune what counts as strong evidence for it."""
    config = _shipped_config()
    config["TcpPortScanDetector"]["unique_ports_threshold"] = 1000
    (tmp_path / CONFIG_FILE_DETECTORS).write_text(json.dumps(config))
    monkeypatch.setattr(reference_thresholds, "CONFIG_DIR", tmp_path)
    reset_cache()

    evidence = {"unique_ports": 60}
    raised_bar = score_alert("TcpPortScanDetector", Severity.HIGH, evidence)

    reset_cache()
    monkeypatch.undo()
    shipped = score_alert("TcpPortScanDetector", Severity.HIGH, evidence)

    # 60 ports is well past a threshold of 15 and well short of one of 1000.
    assert raised_bar < shipped


def test_an_unknown_detector_scores_on_severity_alone() -> None:
    """A third-party detector must still get a usable confidence score."""
    score = score_alert("SomeVendorDetector", Severity.HIGH, {"anything": 999})

    assert 0.0 < score <= 1.0


def test_a_missing_configuration_file_does_not_break_scoring(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """An alert scored on severity alone beats no alert at all."""
    monkeypatch.setattr(reference_thresholds, "CONFIG_DIR", tmp_path)
    reset_cache()

    assert reference_magnitude("TcpPortScanDetector") is None
    assert 0.0 < score_alert("TcpPortScanDetector", Severity.HIGH, {"unique_ports": 60}) <= 1.0
