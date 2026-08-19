"""
Reading the sweep results back, for the notebook and the figures.

Data Setup:  Reads research/sweep_metrics.csv and research/case_outcomes.csv.
Data Input:  A results directory.
Data Output: DataFrames, and the two summary tables the write-up is built on.

The notebook and the figure script both need the same tables, and a table
computed twice is a table that will disagree with itself. Everything either
one reports comes from here.
"""

from pathlib import Path

import pandas as pd

from network_defender.shared.paths import PROJECT_ROOT

from .detectors import shipped_value
from .grid import THRESHOLDS

RESULTS_DIR = PROJECT_ROOT / "research"

#: The evaluation interval in config/setup.json — the window production
#: actually runs with, whatever the per-detector configuration says.
SHIPPED_WINDOW = 5.0


def load_metrics(results_dir: Path = RESULTS_DIR) -> pd.DataFrame:
    """
    Load the grid metrics.

    Args:
        results_dir: Directory holding the committed CSVs.

    Returns:
        One row per grid point.
    """
    return pd.read_csv(results_dir / "sweep_metrics.csv")


def load_outcomes(results_dir: Path = RESULTS_DIR) -> pd.DataFrame:
    """
    Load the per-case outcomes.

    Args:
        results_dir: Directory holding the committed CSVs.

    Returns:
        One row per (detector, window, case).
    """
    return pd.read_csv(results_dir / "case_outcomes.csv")


def shipped_operating_points(metrics: pd.DataFrame) -> pd.DataFrame:
    """
    Return each detector's row at the configuration it actually ships with.

    That is the configured threshold at the *evaluation interval*, not at the
    per-detector `time_window_seconds`, because no detector reads that field.

    Args:
        metrics: The grid metrics.

    Returns:
        One row per swept detector, indexed by detector name.
    """
    wanted = {
        detector: shipped_value(detector, parameter)
        for detector, (parameter, _) in THRESHOLDS.items()
    }
    at_window = metrics[metrics["window_seconds"] == SHIPPED_WINDOW]
    rows = [
        at_window[
            (at_window["detector"] == detector) & (at_window["threshold"] == threshold)
        ]
        for detector, threshold in wanted.items()
    ]
    combined: pd.DataFrame = pd.concat(rows)
    return combined.set_index("detector").sort_index()


def best_operating_points(metrics: pd.DataFrame) -> pd.DataFrame:
    """
    Return the highest-F1 grid point for each detector.

    Ties are broken toward the *higher* threshold and then the *shorter*
    window: among configurations that score the same, the one that alerts less
    and decides sooner is the one an operator should prefer.

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


def window_sensitivity(metrics: pd.DataFrame) -> pd.DataFrame:
    """
    Return the best F1 each detector reaches at each window.

    This is the table that shows the window mattering more than the threshold:
    a detector whose column is flat is one an operator can tune, and one whose
    column climbs with the window is one no threshold can rescue.

    Args:
        metrics: The grid metrics.

    Returns:
        Detectors as rows, windows as columns.
    """
    return (
        metrics.dropna(subset=["f1"])
        .pivot_table(index="detector", columns="window_seconds", values="f1", aggfunc="max")
        .reindex(sorted(THRESHOLDS))
    )
