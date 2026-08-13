"""
Regression: detector output for every capture, compared field by field.

The scenario suite asserts which detectors fire. This one pins what they
*say*: severity, MITRE tactic, the addresses blamed, the description an
analyst reads and the evidence attached to it. Those are the parts a
refactor can quietly change while every "did it fire?" assertion stays green.

To accept a deliberate change:

    ND_REFRESH_GOLDEN=1 uv run pytest tests/e2e/test_golden_detections.py

then read the diff before committing it. A refresh nobody reads is a
regression test that has stopped testing anything.
"""

import pytest

from tests.fixtures.golden import (
    REFRESH_ENV_VAR,
    detections_for,
    golden_path,
    load_golden,
    refresh_requested,
    write_golden,
)
from tests.fixtures.pcaps import SAMPLE_PCAP_DIR

#: Every committed capture, discovered rather than listed, so a new scenario
#: cannot be added to the generator and silently skipped here.
SCENARIOS = sorted(path.stem for path in SAMPLE_PCAP_DIR.glob("*.pcap"))


@pytest.mark.parametrize("scenario", SCENARIOS)
def test_detector_output_matches_the_golden_file(scenario: str) -> None:
    """Detector output must match what was reviewed and committed."""
    actual = detections_for(scenario)

    if refresh_requested():
        write_golden(scenario, actual)
        pytest.skip(f"Refreshed golden file for '{scenario}'.")

    assert actual == load_golden(scenario)


def test_every_capture_has_a_golden_file() -> None:
    """A capture with no expectation is a capture nothing is checking."""
    assert SCENARIOS, "No sample captures found — run scripts/generate_test_pcaps.py."
    missing = [s for s in SCENARIOS if not golden_path(s).exists()]
    assert not missing, (
        f"Missing golden files for {missing}. Create them with: "
        f"{REFRESH_ENV_VAR}=1 uv run pytest tests/e2e/test_golden_detections.py"
    )
