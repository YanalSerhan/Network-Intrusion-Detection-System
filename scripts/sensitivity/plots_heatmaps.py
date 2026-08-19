"""
Parameter-sensitivity heatmaps: F1 over the threshold and window grid.

Data Setup:  Nothing; built from the sweep metrics.
Data Input:  The metrics DataFrame.
Data Output: A Matplotlib figure of one heatmap per detector.

The curves next door hold the window fixed and vary the threshold. These vary
both, which is the only way to see that for most detectors the gradient runs
left to right — along the window — rather than up and down along the number an
operator is actually offered.

Colour is a single hue, light to dark, because F1 is a magnitude. A rainbow
would imply the middle of the range is a different *kind* of result rather
than a smaller one. Cells where the detector never fired are not zero and are
not coloured on the scale: they are drawn in the grid's own grey, because a
detector that made no claim is not the same as one that claimed and was wrong.
"""

from typing import Any

import matplotlib.pyplot as plt
import pandas as pd
from matplotlib.colors import LinearSegmentedColormap
from matplotlib.image import AxesImage
from matplotlib.patches import Rectangle

from .style import FILL_RAMP, GRIDLINE, INK, SURFACE

COLUMNS = 4

#: Above this a threshold is labelled in megabytes; only the exfiltration
#: detector's axis reaches it, and eight digits per tick is unreadable.
MEGABYTE = 1e6

#: A ring is drawn on the row the detector currently ships at, so the reader
#: can see where the configuration sits relative to the good region rather
#: than having to look it up.
RING_WIDTH = 1.4


def _colormap() -> Any:
    """Build the sequential fill from the shared ramp."""
    ramp = LinearSegmentedColormap.from_list("nd_sequential", list(FILL_RAMP))
    ramp.set_bad(GRIDLINE)
    return ramp


def _matrix(metrics: pd.DataFrame, detector: str) -> pd.DataFrame:
    """
    Return F1 as thresholds (rows) by windows (columns) for one detector.

    Reindexed onto the full grid. `pivot_table` drops a row or column that is
    entirely undefined, which for the beaconing detector would silently remove
    the three shortest windows — the panel would then look like every other
    panel while covering a different range, and the missing windows are the
    finding rather than an absence of data.
    """
    rows = metrics[metrics["detector"] == detector]
    table = rows.pivot_table(index="threshold", columns="window_seconds", values="f1")
    return table.reindex(
        index=sorted(rows["threshold"].unique()), columns=sorted(rows["window_seconds"].unique())
    )


def _label(value: float) -> str:
    """Abbreviate a threshold for the axis."""
    return f"{value / MEGABYTE:g}M" if value >= MEGABYTE else f"{value:g}"


def _draw_panel(
    axis: Any, table: pd.DataFrame, detector: str, shipped: float | None
) -> AxesImage:
    """Draw one detector's heatmap and return the image for the colour bar."""
    image: AxesImage = axis.imshow(
        table.to_numpy(), cmap=_colormap(), vmin=0.0, vmax=1.0, aspect="auto", origin="lower"
    )
    axis.set_title(detector.replace("Detector", ""))
    axis.set_xticks(range(len(table.columns)))
    axis.set_xticklabels([f"{value:g}" for value in table.columns], fontsize=6, rotation=45)
    axis.set_yticks(range(len(table.index)))
    axis.set_yticklabels([_label(value) for value in table.index], fontsize=6)
    axis.grid(False)

    if shipped is not None and shipped in table.index:
        row = list(table.index).index(shipped)
        axis.add_patch(
            Rectangle(
                (-0.5, row - 0.5), len(table.columns), 1,
                fill=False, edgecolor=INK, linewidth=RING_WIDTH,
            )
        )
    return image


def f1_heatmaps(metrics: pd.DataFrame, shipped: dict[str, float], title: str) -> Any:
    """
    Draw F1 over the threshold-by-window grid, one panel per detector.

    Args:
        metrics: The grid metrics.
        shipped: Detector -> its configured threshold, outlined on each panel.
        title:   Figure title.

    Returns:
        The figure.
    """
    detectors = sorted(metrics["detector"].unique())
    rows = -(-len(detectors) // COLUMNS)
    figure, axes = plt.subplots(rows, COLUMNS, figsize=(3.1 * COLUMNS, 2.7 * rows), squeeze=False)
    flat = axes.flatten()
    images = [
        _draw_panel(axis, _matrix(metrics, detector), detector, shipped.get(detector))
        for axis, detector in zip(flat, detectors, strict=False)
    ]
    for axis in flat[: len(detectors)]:
        axis.set_xlabel("evaluation window (s)", fontsize=7)

    for axis in flat[len(detectors):]:
        axis.set_visible(False)

    flat[0].set_ylabel("threshold", fontsize=7)
    figure.suptitle(title, fontsize=11, y=1.0)
    figure.tight_layout(rect=(0, 0.09, 1, 1))

    # Its own axes rather than one stolen from the panels: `colorbar(ax=...)`
    # shrinks every panel to make room and lands the bar on top of the bottom
    # row's axis labels.
    bar = figure.colorbar(images[0], cax=figure.add_axes((0.28, 0.035, 0.44, 0.012)),
                          orientation="horizontal")
    bar.set_label("F1  (grey: the detector never fired, so it has no score)", fontsize=7)
    bar.outline.set_edgecolor(SURFACE)
    return figure
