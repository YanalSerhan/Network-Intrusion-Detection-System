"""
Draw every figure in the sensitivity analysis.

Data Setup:  Reads the committed CSVs in research/.
Data Input:  An optional output directory (defaults to docs/images).
Data Output: One PNG per figure.

Usage:
    uv run python scripts/make_sensitivity_figures.py [--output-dir DIR]

Figures are committed alongside the data they are drawn from, so the write-up
in docs/ renders without anyone running a notebook, and so a change in
detector behaviour shows up as a changed picture in the same commit as the
changed numbers.
"""

import argparse
from pathlib import Path

import matplotlib
import pandas as pd

# Headless: this runs in CI and over SSH, where importing pyplot against an
# interactive backend fails rather than degrading.
matplotlib.use("Agg")

from sensitivity.analysis import SHIPPED_WINDOW, best_operating_points, load_metrics
from sensitivity.detectors import shipped_value
from sensitivity.grid import THRESHOLDS, WINDOWS
from sensitivity.plots_curves import precision_recall_grid, roc_grid
from sensitivity.plots_heatmaps import f1_heatmaps
from sensitivity.plots_timeline import alert_volume
from sensitivity.scenario import DURATION, attack_spans
from sensitivity.style import FIGURE_DIR, apply_style, save

from network_defender.shared.paths import PROJECT_ROOT

DEFAULT_OUTPUT_DIR = PROJECT_ROOT / FIGURE_DIR


def draw_curves(output_dir: Path) -> None:
    """
    Draw the precision/recall and ROC-style figures.

    Args:
        output_dir: Where the PNGs are written.
    """
    metrics = load_metrics()
    best = best_operating_points(metrics)

    save(
        precision_recall_grid(
            metrics,
            dict.fromkeys(THRESHOLDS, SHIPPED_WINDOW),
            "Precision and recall against threshold, at the 5-second window production uses",
        ),
        str(output_dir / "precision_recall_shipped_window.png"),
    )
    save(
        precision_recall_grid(
            metrics,
            {name: float(best.loc[name, "window_seconds"]) for name in best.index},
            "Precision and recall against threshold, each detector at its best window",
        ),
        str(output_dir / "precision_recall_best_window.png"),
    )
    save(
        roc_grid(
            metrics,
            WINDOWS,
            "Recall against false-positive rate, one curve per evaluation window",
        ),
        str(output_dir / "roc_by_window.png"),
    )


def draw_heatmaps(output_dir: Path) -> None:
    """
    Draw the parameter-sensitivity heatmaps.

    Args:
        output_dir: Where the PNG is written.
    """
    metrics = load_metrics()
    shipped = {
        detector: float(shipped_value(detector, parameter))
        for detector, (parameter, _) in THRESHOLDS.items()
    }
    save(
        f1_heatmaps(
            metrics,
            shipped,
            "F1 over threshold and evaluation window "
            "(outlined row: the configured threshold)",
        ),
        str(output_dir / "f1_threshold_window_heatmaps.png"),
    )


def draw_timeline(output_dir: Path) -> None:
    """
    Draw alert volume over the composed timeline.

    Args:
        output_dir: Where the PNG is written.
    """
    rows = pd.read_csv(PROJECT_ROOT / "research" / "alert_timeline.csv")
    save(
        alert_volume(
            rows,
            attack_spans(),
            DURATION,
            "Alerts raised over half an hour of traffic containing five attacks",
        ),
        str(output_dir / "alert_volume_timeline.png"),
    )


def main() -> None:
    """Parse arguments and draw every figure."""
    parser = argparse.ArgumentParser(description="Draw the sensitivity-analysis figures.")
    parser.add_argument("--output-dir", type=Path, default=DEFAULT_OUTPUT_DIR)
    output_dir = parser.parse_args().output_dir
    output_dir.mkdir(parents=True, exist_ok=True)

    apply_style()
    draw_curves(output_dir)
    draw_heatmaps(output_dir)
    draw_timeline(output_dir)


if __name__ == "__main__":
    main()
