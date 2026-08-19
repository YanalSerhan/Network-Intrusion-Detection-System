"""
Replaying the composed timeline and recording when each alert surfaced.

Data Setup:  Nothing; the scenario is built next door in `scenario`.
Data Input:  A parsed timeline, an evaluation interval, threshold overrides.
Data Output: One row per alert raised.

Every detector is run, not just the swept ones: the question here is what an
operator's console shows, and it shows all of them. Each alert is tagged with
whether an attack the detector is responsible for was running inside the
window that produced it, which is the analyst's version of precision — the
untagged ones are what someone reads and dismisses.
"""

from typing import Any

from network_defender.parser.models import ParsedPacket

from .detectors import build, detector_names
from .grid import THRESHOLDS
from .harness import replay_timeline
from .scenario import BY_NAME, attack_spans


def _attributable(detector: str, raised_at: float, window: float) -> bool:
    """Return True if an attack this detector is responsible for was running."""
    return any(
        detector in BY_NAME[name].expected and start < raised_at and end > raised_at - window
        for name, start, end in attack_spans()
    )


def run(
    packets: list[ParsedPacket], window: float, thresholds: dict[str, int], label: str
) -> list[dict[str, Any]]:
    """
    Replay the timeline through every detector at one configuration.

    Args:
        packets:    The composed, parsed timeline.
        window:     Evaluation interval in seconds.
        thresholds: Detector -> threshold override; detectors absent from it
                    keep their shipped value.
        label:      Name for this configuration, carried on every row.

    Returns:
        One row per alert raised.
    """
    rows: list[dict[str, Any]] = []
    for name in detector_names():
        parameter = THRESHOLDS.get(name, (None, ()))[0]
        overrides = (
            {parameter: thresholds[name]} if parameter and name in thresholds else {}
        )
        for raised_at, alert in replay_timeline(build(name, **overrides), packets, window):
            rows.append({
                "config": label,
                "raised_at": raised_at,
                "detector": alert.detector_name,
                "attributable": int(_attributable(name, raised_at, window)),
            })
    return rows
