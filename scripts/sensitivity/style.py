"""
One visual system for every figure in the analysis.

Data Setup:  Nothing; constants and a Matplotlib rcParams block.
Data Input:  None.
Data Output: Colours, and a configured pyplot.

Colours are not chosen per chart. Each slot below has a job — two categorical
hues for series identity, one ordered blue ramp for magnitude, muted greys for
chrome — and a figure picks by the job rather than by taste. The categorical
pair was checked for colour-vision separation rather than eyeballed: blue
against orange measures a protanopia delta-E of 24.7 and a normal-vision
delta-E of 33.6, both well clear of the floors.

No backend is chosen here. A notebook wants its frontend's inline backend and
a script wants a headless one; a module that picks for both would silently
stop rendering figures in one of them.

The ramp starts at a mid step rather than at white. The lightest steps of a
sequential scale are for continuous fills where "near zero" is allowed to
recede into the page; a line has to stay visible against it.
"""

from typing import Any

import matplotlib.pyplot as plt

#: Series identity. Two, deliberately: a chart needing a third is a chart that
#: should have been small multiples.
PRECISION_COLOR = "#2a78d6"
RECALL_COLOR = "#eb6834"

#: Ordered magnitude — the evaluation window, shortest to longest. One hue,
#: light to dark, because the window is a quantity rather than a category.
WINDOW_RAMP = ("#86b6ef", "#6da7ec", "#3987e5", "#2a78d6", "#1c5cab", "#184f95", "#0d366b")

#: Sequential fill for the heatmaps, light to dark over the same hue.
FILL_RAMP = (
    "#cde2fb", "#b7d3f6", "#9ec5f4", "#86b6ef", "#6da7ec", "#5598e7",
    "#3987e5", "#2a78d6", "#256abf", "#1c5cab", "#184f95", "#104281", "#0d366b",
)

SURFACE = "#fcfcfb"
INK = "#0b0b0b"
SECONDARY_INK = "#52514e"
MUTED = "#898781"
GRIDLINE = "#e1e0d9"
AXIS = "#c3c2b7"

#: Where committed figures are written. Under docs/ because they are read as
#: part of the write-up, not as build output.
FIGURE_DIR = "docs/images"


def apply_style() -> None:
    """Configure Matplotlib so every figure shares one visual system."""
    plt.rcParams.update({
        "figure.facecolor": SURFACE,
        "axes.facecolor": SURFACE,
        "savefig.facecolor": SURFACE,
        "font.family": "sans-serif",
        "font.size": 8,
        "text.color": INK,
        "axes.labelcolor": SECONDARY_INK,
        "axes.edgecolor": AXIS,
        "axes.linewidth": 0.8,
        "axes.titlesize": 9,
        "axes.titlecolor": INK,
        "axes.grid": True,
        "axes.spines.top": False,
        "axes.spines.right": False,
        "grid.color": GRIDLINE,
        "grid.linewidth": 0.6,
        "xtick.color": MUTED,
        "ytick.color": MUTED,
        "xtick.labelcolor": SECONDARY_INK,
        "ytick.labelcolor": SECONDARY_INK,
        "legend.frameon": False,
        "lines.linewidth": 2.0,
        "lines.markersize": 4.5,
        # Screen density for the inline figure a notebook embeds; the saved
        # file gets its own, higher, density below. One setting for both makes
        # either the notebook heavy or the committed PNG soft.
        "figure.dpi": 110,
        "savefig.dpi": 200,
    })


def window_color(index: int) -> str:
    """
    Return the ramp step for a window, shortest window lightest.

    Args:
        index: Position in the ordered window list.

    Returns:
        A hex colour.
    """
    return WINDOW_RAMP[min(index, len(WINDOW_RAMP) - 1)]


def save(figure: Any, path: str) -> None:
    """
    Write a figure and close it.

    Args:
        figure: The Matplotlib figure.
        path:   Destination path.
    """
    figure.savefig(path, bbox_inches="tight")
    plt.close(figure)
    print(f"wrote {path}")
