"""
Detector threshold sensitivity analysis (Milestone 19).

Data Setup:  Nothing at import time beyond assembling the corpus.
Data Input:  None.
Data Output: The corpus, the grid, and the sweep that joins them.

The package answers one question: for each detector, what does moving its
threshold cost and buy? Answering it needs three things that did not exist
before — traffic that is labelled rather than merely synthetic, benign traffic
shaped like an attack so a false positive is possible at all, and a replay
harness that applies the evaluation window explicitly.

See docs/SENSITIVITY_ANALYSIS.md for the method and docs/DETECTION_TUNING.md
for what the numbers came out as.
"""

from .case import Case
from .corpus import CORPUS, check_labels
from .grid import THRESHOLDS, UNSWEPT, WINDOWS
from .metrics import Confusion
from .sweep import sweep

__all__ = [
    "CORPUS",
    "THRESHOLDS",
    "UNSWEPT",
    "WINDOWS",
    "Case",
    "Confusion",
    "check_labels",
    "sweep",
]
