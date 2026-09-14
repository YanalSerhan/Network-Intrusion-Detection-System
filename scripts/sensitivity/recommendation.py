"""
Turning the sweep into a configuration a sensor could actually run.

Data Setup:  Nothing; derived from the committed metrics.
Data Input:  The metrics DataFrame.
Data Output: A window and a threshold per detector.

Until Milestone 21 there was one knob to recommend and it had to serve every
detector at once: no detector read its own `time_window_seconds`, so the only
live control was the shared evaluation interval. Picking it per detector and
reporting that as a recommendation would have been recommending something the
code could not do.

Now the window is per detector and the interval is only how often each is
asked, so a recommendation is a pair per detector — which is both more useful
and, finally, implementable.

A detector that never fires scores no F1. Where that has to be averaged it is
treated as 0.0 rather than dropped, because a detector going silent is the
worst outcome available and averaging it away would hide it.
"""

import pandas as pd


def best_f1_points(metrics: pd.DataFrame) -> pd.DataFrame:
    """
    Return the highest-F1 (window, threshold) for each detector.

    Ties break toward the higher threshold and then the shorter window: among
    configurations that score the same, prefer the one that alerts less and
    decides sooner.

    Args:
        metrics: The grid metrics.

    Returns:
        One row per detector that scored at all, indexed by detector name.
    """
    scored = metrics.dropna(subset=["f1"])
    ordered = scored.sort_values(
        ["detector", "f1", "threshold", "window_seconds"],
        ascending=[True, False, False, True],
    )
    return ordered.groupby("detector", as_index=True).first()


def clean_points(metrics: pd.DataFrame, windows: dict[str, float]) -> pd.DataFrame:
    """
    Return the most sensitive threshold that alerts on no benign case.

    Evaluated at each detector's *own* window rather than across the grid.
    Searching both axes at once finds operating points that are clean only
    because the window is too short for anything to accumulate, which is a
    way of scoring well by not looking.

    The F1 optimum is the other end and is no better on its own: it maximises
    a score computed on a corpus that is half attacks, so it systematically
    prices a false positive against twenty-three negative cases when a real
    segment offers millions.

    "No false positive here" is a necessary condition, not a sufficient one.
    Twenty-three benign cases cannot certify a detector against real traffic.

    Args:
        metrics: The grid metrics.
        windows: Detector -> the window to evaluate it at.

    Returns:
        One row per detector that can both fire and stay clean at its window.
    """
    rows = [
        metrics[
            (metrics["detector"] == detector)
            & (metrics["window_seconds"] == window)
            & (metrics["false_positives"] == 0)
            & (metrics["true_positives"] > 0)
        ]
        for detector, window in windows.items()
    ]
    candidates = pd.concat(rows)
    ordered = candidates.sort_values(
        ["detector", "recall", "threshold"], ascending=[True, False, True]
    )
    return ordered.groupby("detector", as_index=True).first()


def benign_ceiling(outcomes: pd.DataFrame, windows: dict[str, float]) -> pd.Series:
    """
    Return the largest magnitude any benign case reaches, per detector.

    This is what a threshold needs headroom over, and quoting the margin is
    the difference between a recommendation and a number fitted to one
    fixture's volume.

    Args:
        outcomes: The per-case outcomes.
        windows:  Detector -> the window to read it at.

    Returns:
        Detector -> the highest threshold a benign case still fires at.
    """
    benign = outcomes[
        (outcomes["expected"] == 0) & outcomes["highest_firing_threshold"].notna()
    ]
    at_window = benign[
        benign.apply(lambda row: windows.get(row["detector"]) == row["window_seconds"], axis=1)
    ]
    ceilings: pd.Series = at_window.groupby("detector")["highest_firing_threshold"].max()
    return ceilings
