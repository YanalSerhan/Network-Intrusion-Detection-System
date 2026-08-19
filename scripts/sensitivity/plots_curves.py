"""
Precision/recall curves and ROC-style curves, as small multiples.

Data Setup:  Nothing; every figure is built from the sweep metrics.
Data Input:  The metrics DataFrame.
Data Output: Matplotlib figures.

Twelve detectors will not fit on one pair of axes: twelve colours is past
every separation floor a colour-vision check applies, and the reader's
question is about one detector at a time anyway. One panel per detector, the
same scales throughout, so panels can be compared by eye.

Thresholds are drawn at even spacing rather than to scale. The grids are
uneven by design — dense around the shipped value, sparse at the extremes —
and plotting them to scale would compress the interesting region into the
left margin. The tick labels carry the real values.
"""

from typing import Any

import matplotlib.pyplot as plt
import pandas as pd
from matplotlib.lines import Line2D

from .style import PRECISION_COLOR, RECALL_COLOR, window_color

#: Above this, a threshold is labelled in megabytes: only the exfiltration
#: detector's axis reaches it, and eight digits per tick is unreadable.
MEGABYTE = 1_000_000

#: Four across, three down: twelve detectors, and a shape that stays legible
#: at the width of a document page.
COLUMNS = 4


def _panel_grid(count: int, height: float) -> tuple[Any, Any]:
    """Create a small-multiples grid sized for `count` panels."""
    rows = -(-count // COLUMNS)
    figure, axes = plt.subplots(
        rows, COLUMNS, figsize=(3.1 * COLUMNS, height * rows), squeeze=False
    )
    return figure, axes.flatten()


def _tick_labels(values: list[int]) -> list[str]:
    """Abbreviate large thresholds so the axis stays readable."""
    return [f"{value // MEGABYTE}M" if value >= MEGABYTE else str(value) for value in values]


def precision_recall_grid(
    metrics: pd.DataFrame, windows: dict[str, float], title: str
) -> Any:
    """
    Draw precision and recall against threshold, one panel per detector.

    Args:
        metrics: The grid metrics.
        windows: Detector -> the evaluation window to draw it at.
        title:   Figure title; it must say which window the panels use.

    Returns:
        The figure.
    """
    detectors = sorted(windows)
    figure, axes = _panel_grid(len(detectors), 2.5)

    for axis, detector in zip(axes, detectors, strict=False):
        rows = metrics[
            (metrics["detector"] == detector)
            & (metrics["window_seconds"] == windows[detector])
        ].sort_values("threshold")
        positions = range(len(rows))
        axis.plot(positions, rows["precision"], color=PRECISION_COLOR, marker="o")
        axis.plot(positions, rows["recall"], color=RECALL_COLOR, marker="o")
        axis.set_title(f"{detector.replace('Detector', '')}\n{windows[detector]:g}s window")
        axis.set_ylim(-0.05, 1.05)
        axis.set_xticks(list(positions))
        axis.set_xticklabels(_tick_labels(rows["threshold"].tolist()), fontsize=6)

    for axis in axes[len(detectors):]:
        axis.set_visible(False)

    figure.suptitle(title, fontsize=11, y=1.0)
    figure.legend(
        handles=[
            Line2D([], [], color=PRECISION_COLOR, marker="o", label="precision"),
            Line2D([], [], color=RECALL_COLOR, marker="o", label="recall"),
        ],
        loc="lower center",
        ncol=2,
        bbox_to_anchor=(0.5, -0.02),
    )
    figure.tight_layout()
    return figure


def roc_grid(metrics: pd.DataFrame, windows: tuple[float, ...], title: str) -> Any:
    """
    Draw a ROC-style curve per detector, one line per evaluation window.

    There is no chance diagonal. Every false-positive rate here is under 0.06,
    because the corpus has forty-odd negative cases and a detector alerts on
    at most two of them, so an axis running to 1.0 would compress every curve
    onto the y-axis. On a clipped axis the diagonal is not the chance line —
    it is a line at the wrong slope inviting the wrong comparison.

    Args:
        metrics: The grid metrics.
        windows: Windows to draw, shortest first — the ramp encodes the order.
        title:   Figure title.

    Returns:
        The figure.
    """
    detectors = sorted(metrics["detector"].unique())
    figure, axes = _panel_grid(len(detectors), 2.6)
    widest = float(metrics["false_positive_rate"].max())

    for position, (axis, detector) in enumerate(zip(axes, detectors, strict=False)):
        for index, window in enumerate(windows):
            rows = metrics[
                (metrics["detector"] == detector) & (metrics["window_seconds"] == window)
            ].sort_values("threshold", ascending=False)
            axis.plot(
                rows["false_positive_rate"], rows["recall"],
                color=window_color(index), marker="o", markersize=3.5,
                linewidth=1.6, alpha=0.85, solid_capstyle="round",
            )
        axis.set_title(detector.replace("Detector", ""))
        axis.set_xlim(-widest * 0.08, widest * 1.08)
        axis.set_ylim(-0.05, 1.05)
        axis.set_xlabel("false-positive rate", fontsize=7)
        if position % COLUMNS == 0:
            axis.set_ylabel("recall", fontsize=7)

    for axis in axes[len(detectors):]:
        axis.set_visible(False)

    figure.suptitle(title, fontsize=11, y=1.0)
    figure.tight_layout(rect=(0, 0.05, 1, 1))
    figure.legend(
        handles=[
            Line2D([], [], color=window_color(index), marker="o", label=f"{window:g}s")
            for index, window in enumerate(windows)
        ],
        loc="lower center", ncol=len(windows), bbox_to_anchor=(0.5, 0.0),
        title="evaluation window",
    )
    return figure
