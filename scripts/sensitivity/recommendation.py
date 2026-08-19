"""
Turning the sweep into one configuration a sensor could actually run.

Data Setup:  Nothing; derived from the committed metrics.
Data Input:  The metrics DataFrame.
Data Output: One evaluation interval, and one threshold per detector.

The sweep gives every detector its own best window, and that is not a
configuration: `PeriodicEvaluator` runs one timer for all of them, so there is
exactly one interval to choose. Picking it per detector and reporting the
result as a recommendation would be recommending something the code cannot
do — the same class of mistake as a `time_window_seconds` nobody reads.

A detector that never fires scores no F1. Here that is treated as 0.0 rather
than dropped, because when the question is which single interval to run, a
detector going silent is the worst outcome available and averaging it away
would hide it.
"""

import pandas as pd

from .grid import THRESHOLDS


def window_scores(metrics: pd.DataFrame) -> pd.Series:
    """
    Return the mean best-F1 across detectors, for each candidate interval.

    Args:
        metrics: The grid metrics.

    Returns:
        Interval in seconds -> mean F1, undefined counted as zero.
    """
    best_per_detector = (
        metrics.pivot_table(
            index="detector", columns="window_seconds", values="f1", aggfunc="max"
        )
        .reindex(sorted(THRESHOLDS))
        .fillna(0.0)
    )
    return best_per_detector.mean(axis=0)


def best_common_window(metrics: pd.DataFrame) -> float:
    """
    Return the single evaluation interval that serves every detector best.

    Ties break toward the shorter interval: the interval is also the detection
    latency, so two configurations that score the same are not equally good to
    run.

    Args:
        metrics: The grid metrics.

    Returns:
        The interval in seconds.
    """
    scores = window_scores(metrics)
    top = scores.max()
    # The index is the window in seconds; pandas types it as Hashable, so the
    # cast says what the column already guarantees.
    winners = [float(str(window)) for window, score in scores.items() if score == top]
    return min(winners)


def recommended_thresholds(metrics: pd.DataFrame, window: float) -> dict[str, int]:
    """
    Return the best threshold for each detector at one shared interval.

    Ties break toward the *higher* threshold: among configurations that score
    the same, the one that alerts less is the one an analyst should be given.

    Args:
        metrics: The grid metrics.
        window:  The evaluation interval to tune against.

    Returns:
        Detector name -> recommended threshold.
    """
    at_window = metrics[metrics["window_seconds"] == window].dropna(subset=["f1"])
    ordered = at_window.sort_values(
        ["detector", "f1", "threshold"], ascending=[True, False, False]
    )
    chosen = ordered.groupby("detector")["threshold"].first()
    return {str(detector): int(value) for detector, value in chosen.items()}


def precision_first_thresholds(metrics: pd.DataFrame, window: float) -> dict[str, int]:
    """
    Return the most sensitive threshold that alerts on no benign case.

    The F1 optimum above maximises a score computed on a corpus that is half
    attacks. Production is not, so that score systematically favours a lowered
    threshold: it prices a false positive against twenty-three negative cases
    when a real segment offers millions. This picks the other end — the most
    recall available while the detector stays silent on every benign case in
    the corpus — which is the operating point an analyst's attention budget
    argues for.

    "No false positive here" is a necessary condition, not a sufficient one.
    Twenty-three benign cases cannot certify a detector against real traffic.

    Args:
        metrics: The grid metrics.
        window:  The evaluation interval to tune against.

    Returns:
        Detector -> threshold. Detectors that cannot both fire and stay clean
        at this window are absent.
    """
    clean = metrics[
        (metrics["window_seconds"] == window)
        & (metrics["false_positives"] == 0)
        & (metrics["true_positives"] > 0)
    ]
    # Recall first, then the *lowest* threshold that achieves it. Several
    # thresholds usually tie at the same clean recall, and among them the
    # lowest is the most sensitive at no measured cost — the opposite
    # tie-break from `recommended_thresholds`, where the alternatives differ
    # in how much they alert.
    ordered = clean.sort_values(["detector", "recall", "threshold"], ascending=[True, False, True])
    chosen = ordered.groupby("detector")["threshold"].first()
    return {str(detector): int(value) for detector, value in chosen.items()}
