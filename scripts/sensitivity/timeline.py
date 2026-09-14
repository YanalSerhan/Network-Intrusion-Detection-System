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
from .harness import replay_timeline
from .scenario import BY_NAME, attack_spans


def _attributable(detector: str, raised_at: float, lookback: float) -> bool:
    """
    Return True if an attack this detector is responsible for was running.

    Args:
        detector:  The detector that raised the alert.
        raised_at: Seconds into the timeline at which the evaluation ran.
        lookback:  How far back the alert can be about.

    Returns:
        Whether an attack overlaps that span.
    """
    return any(
        detector in BY_NAME[name].expected and start < raised_at and end > raised_at - lookback
        for name, start, end in attack_spans()
    )


def run(
    packets: list[ParsedPacket],
    interval: float,
    overrides: dict[str, dict[str, Any]],
    label: str,
) -> list[dict[str, Any]]:
    """
    Replay the timeline through every detector at one configuration.

    Args:
        packets:   The composed, parsed timeline.
        interval:  Seconds of capture time between evaluations.
        overrides: Detector -> configuration overrides. A detector absent from
                   it keeps everything shipped; a detector present may override
                   its threshold, its `time_window_seconds`, or both. Both,
                   because since Milestone 21 a configuration is a window *and*
                   a threshold per detector rather than one shared interval.
        label:     Name for this configuration, carried on every row.

    Returns:
        One row per alert raised.
    """
    rows: list[dict[str, Any]] = []
    for name in detector_names():
        detector = build(name, **overrides.get(name, {}))
        for raised_at, alert in replay_timeline(detector, packets, interval):
            rows.append({
                "config": label,
                "raised_at": raised_at,
                "detector": alert.detector_name,
                # An alert cannot surface before the next evaluation, so a
                # detector with a window shorter than the interval reports a
                # burst that has already left its window. Attributing against
                # the window alone would score those as false positives —
                # which is how a one-second flood detector came out looking
                # wrong for catching a flood.
                "attributable": int(
                    _attributable(name, raised_at, max(detector.window_seconds, interval))
                ),
            })
    return rows
