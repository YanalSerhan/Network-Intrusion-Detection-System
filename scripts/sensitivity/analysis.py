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
from sensitivity.detectors import shipped_value
from sensitivity.grid import THRESHOLDS

RESULTS_DIR = PROJECT_ROOT / "research"

#: The evaluation interval in config/setup.json. Since Milestone 21 this is
#: how often a detector is asked, not how much it considers, so it no longer
#: appears on any axis — it is kept because the timeline reports alert times
#: in multiples of it.
EVALUATION_INTERVAL = 5.0


def shipped_windows() -> dict[str, float]:
    """
    Return each detector's configured window.

    Returns:
        Detector -> `time_window_seconds` from config/detectors.json. Before
        Milestone 21 this function could not have existed: the field was
        declared, validated and read by nothing, so every detector's real
        window was the shared evaluation interval.
    """
    return {
        detector: float(shipped_value(detector, "time_window_seconds"))
        for detector in THRESHOLDS
    }


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

    The configured threshold at the configured window — which is only a
    meaningful pair since Milestone 21, when detectors started reading the
    window their own configuration declares.

    Args:
        metrics: The grid metrics.

    Returns:
        One row per swept detector, indexed by detector name.
    """
    windows = shipped_windows()
    rows = [
        metrics[
            (metrics["detector"] == detector)
            & (metrics["window_seconds"] == windows[detector])
            & (metrics["threshold"] == shipped_value(detector, parameter))
        ]
        for detector, (parameter, _) in THRESHOLDS.items()
    ]
    combined: pd.DataFrame = pd.concat(rows)
    return combined.set_index("detector").sort_index()


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
