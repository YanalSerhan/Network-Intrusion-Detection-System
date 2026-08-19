"""
Alert volume over a composed half-hour, at two configurations.

Data Setup:  Nothing; built from the timeline rows.
Data Input:  The alert rows and the attack spans.
Data Output: A Matplotlib figure, one panel per configuration.

The bars are split by whether an attack the detector is responsible for was
running when the alert surfaced. That split is the analyst's version of
precision: the orange is what someone reads and dismisses, and it accumulates
whether or not an attack ever happens.

Shaded bands mark the attacks. They are drawn behind the bars and in the
chart's own grey rather than in a series colour — they are context, and giving
them a hue would make them look like a third series.
"""

from typing import Any

import matplotlib.pyplot as plt
import pandas as pd
from matplotlib.lines import Line2D
from matplotlib.patches import Patch

from .style import GRIDLINE, INK, MUTED, PRECISION_COLOR, RECALL_COLOR

#: One bar per half-minute. Fine enough to separate the five attacks, coarse
#: enough that a five-minute evaluation interval still lands in its own bar.
BUCKET_SECONDS = 30.0


def _volume(rows: pd.DataFrame, duration: float) -> pd.DataFrame:
    """Count alerts per bucket, split by whether an attack was running."""
    buckets = pd.Series(
        list(range(0, int(duration), int(BUCKET_SECONDS))), name="bucket"
    )
    binned = (rows["raised_at"] // BUCKET_SECONDS * BUCKET_SECONDS).astype(int)
    counted = (
        rows.assign(bucket=binned)
        .pivot_table(index="bucket", columns="attributable", values="detector", aggfunc="count")
        .reindex(buckets, fill_value=0)
        .fillna(0)
    )
    for column in (0, 1):
        if column not in counted.columns:
            counted[column] = 0
    return counted


def alert_volume(
    rows: pd.DataFrame, spans: list[tuple[str, float, float]], duration: float, title: str
) -> Any:
    """
    Draw alert volume over time, one panel per configuration.

    Args:
        rows:     One row per alert, with `config`, `raised_at`, `attributable`.
        spans:    (name, start, end) for each attack on the timeline.
        duration: Length of the timeline in seconds.
        title:    Figure title.

    Returns:
        The figure.
    """
    configs = list(dict.fromkeys(rows["config"]))
    figure, axes = plt.subplots(
        len(configs), 1, figsize=(11, 2.9 * len(configs)), sharex=True, sharey=True, squeeze=False
    )

    for axis, config in zip(axes.flatten(), configs, strict=False):
        counted = _volume(rows[rows["config"] == config], duration)
        for _, start, end in spans:
            axis.axvspan(start, end, color=GRIDLINE, zorder=0)
        axis.bar(
            counted.index, counted[1], width=BUCKET_SECONDS * 0.9,
            color=PRECISION_COLOR, zorder=2,
        )
        axis.bar(
            counted.index, counted[0], bottom=counted[1], width=BUCKET_SECONDS * 0.9,
            color=RECALL_COLOR, zorder=2,
        )
        # Inside the axes rather than as a title: the attack labels above the
        # top panel need the whole title strip, and a title there collides
        # with the first of them.
        axis.text(
            0.006, 0.9, config, transform=axis.transAxes,
            fontsize=9, va="top", ha="left", color=INK,
        )
        axis.set_ylabel("alerts", fontsize=8)
        axis.set_xlim(0, duration)

    for name, start, end in spans:
        axes.flatten()[0].annotate(
            name.replace("_", " "),
            xy=((start + end) / 2, axes.flatten()[0].get_ylim()[1]),
            xytext=(0, 6), textcoords="offset points",
            ha="center", va="bottom", fontsize=6, color=MUTED, rotation=20,
        )

    axes.flatten()[-1].set_xlabel("seconds into the capture", fontsize=8)
    figure.suptitle(title, fontsize=11)
    figure.tight_layout(rect=(0, 0.07, 1, 0.94))
    figure.legend(
        handles=[
            Patch(facecolor=PRECISION_COLOR, label="an attack was running"),
            Patch(facecolor=RECALL_COLOR, label="nothing was happening"),
            Line2D([], [], color=GRIDLINE, linewidth=8, label="attack in progress"),
        ],
        loc="lower center", ncol=3, bbox_to_anchor=(0.5, 0.0),
    )
    return figure
