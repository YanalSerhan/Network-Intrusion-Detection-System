"""
Running the grid: every detector, at every threshold, over every window.

Data Setup:  The corpus is built and parsed once, then reused for every point.
Data Input:  The grids in `grid`.
Data Output: One metrics row per grid point, and one outcome row per
             (detector, window, case).

Parsing is hoisted out of the loop deliberately. A grid point differs from its
neighbour only in a configuration value, so re-parsing the same packets nine
hundred times would make the experiment slow enough to be run less often,
which is the practical way a sensitivity analysis stops being repeated.

Firing is monotone in every threshold here — raising it can only silence a
detector, never wake it — so each (detector, window, case) is summarised by
the highest threshold at which it still fires. `_summarise` checks that
monotonicity rather than assuming it: a detector whose behaviour is not
monotone would make every curve below meaningless, and it should say so.
"""

from typing import Any

from network_defender.parser.models import ParsedPacket

from .case import Case
from .corpus import CORPUS
from .detectors import build
from .grid import THRESHOLDS, WINDOWS
from .harness import parse_case, replay
from .metrics import Confusion

Row = dict[str, Any]


def parse_corpus(cases: list[Case]) -> dict[str, list[ParsedPacket]]:
    """
    Build and parse every case once.

    Args:
        cases: The corpus.

    Returns:
        Case name -> parsed packets in capture order.
    """
    return {case.name: parse_case(case) for case in cases}


def _fires(detector_name: str, parameter: str, value: int, window: float,
           packets: list[ParsedPacket]) -> bool:
    """Return True if a freshly configured detector alerts on these packets."""
    detector = build(detector_name, **{parameter: value})
    return bool(replay(detector, packets, window))


def _summarise(firing: dict[int, bool], thresholds: tuple[int, ...]) -> int | None:
    """
    Reduce a threshold -> fired mapping to the highest firing threshold.

    Args:
        firing:     Whether the detector fired at each threshold tried.
        thresholds: The thresholds tried, ascending.

    Returns:
        The highest threshold that still fired, or None if none did.

    Raises:
        ValueError: If firing is not monotone in the threshold, which would
            invalidate every curve derived from this summary.
    """
    fired = [value for value in thresholds if firing[value]]
    if not fired:
        return None
    highest = max(fired)
    silent_below = [value for value in thresholds if value <= highest and not firing[value]]
    if silent_below:
        raise ValueError(
            f"Non-monotone firing: silent at {silent_below} but firing at {highest}."
        )
    return highest


def sweep(cases: list[Case] | None = None) -> tuple[list[Row], list[Row]]:
    """
    Run the whole grid.

    Args:
        cases: Corpus override, for tests. Defaults to the full corpus.

    Returns:
        (metrics rows, outcome rows).
    """
    corpus = cases if cases is not None else CORPUS
    parsed = parse_corpus(corpus)
    metrics: list[Row] = []
    outcomes: list[Row] = []

    for detector_name, (parameter, thresholds) in sorted(THRESHOLDS.items()):
        for window in WINDOWS:
            tallies = {value: Confusion() for value in thresholds}
            for case in corpus:
                firing = {
                    value: _fires(detector_name, parameter, value, window, parsed[case.name])
                    for value in thresholds
                }
                expected = detector_name in case.expected
                for value in thresholds:
                    tallies[value] = tallies[value].record(expected, firing[value])
                outcomes.append(
                    _outcome_row(detector_name, window, case, _summarise(firing, thresholds))
                )
            metrics.extend(
                _metrics_row(detector_name, parameter, value, window, tallies[value])
                for value in thresholds
            )
    return metrics, outcomes


def _outcome_row(detector: str, window: float, case: Case, highest: int | None) -> Row:
    """Build one row describing how a case behaved at one window."""
    return {
        "detector": detector,
        "window_seconds": window,
        "case": case.name,
        "family": case.family,
        "expected": int(detector in case.expected),
        "highest_firing_threshold": highest,
    }


def _metrics_row(detector: str, parameter: str, value: int, window: float,
                 tally: Confusion) -> Row:
    """Build one metrics row for a grid point."""
    return {
        "detector": detector,
        "parameter": parameter,
        "threshold": value,
        "window_seconds": window,
        "true_positives": tally.true_positives,
        "false_positives": tally.false_positives,
        "false_negatives": tally.false_negatives,
        "true_negatives": tally.true_negatives,
        "precision": tally.precision,
        "recall": tally.recall,
        "false_positive_rate": tally.false_positive_rate,
        "f1": tally.f1,
    }
