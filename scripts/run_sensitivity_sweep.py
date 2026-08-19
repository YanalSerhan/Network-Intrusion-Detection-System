"""
Run the detector threshold sweep and write the results.

Data Setup:  None; the corpus is generated in memory from a fixed seed.
Data Input:  An optional output directory (defaults to research/).
Data Output: sweep_metrics.csv and case_outcomes.csv.

Usage:
    uv run python scripts/run_sensitivity_sweep.py [--output-dir DIR]

Results are committed rather than regenerated on demand, for the same reason
the sample captures are: a change in detector behaviour should arrive as a
diff someone reads, not as a number that quietly moved. The corpus is seeded,
so a re-run with unchanged detectors produces an identical file.

See docs/SENSITIVITY_ANALYSIS.md for the method.
"""

import argparse
import csv
from pathlib import Path
from typing import Any

from sensitivity.corpus import CORPUS, check_labels
from sensitivity.detectors import detector_names
from sensitivity.sweep import sweep

DEFAULT_OUTPUT_DIR = Path(__file__).resolve().parent.parent / "research"

METRIC_FIELDS = [
    "detector", "parameter", "threshold", "window_seconds",
    "true_positives", "false_positives", "false_negatives", "true_negatives",
    "precision", "recall", "false_positive_rate", "f1",
]

OUTCOME_FIELDS = [
    "detector", "window_seconds", "case", "family", "expected",
    "highest_firing_threshold",
]

#: Rates are written to this many places. Every denominator here is a case
#: count under fifty, so anything finer would be printing float noise.
PLACES = 6


def _rounded(row: dict[str, Any]) -> dict[str, Any]:
    """Round the float fields, leaving None as an empty cell."""
    return {
        key: round(value, PLACES) if isinstance(value, float) else value
        for key, value in row.items()
    }


def _write(path: Path, fields: list[str], rows: list[dict[str, Any]]) -> None:
    """Write rows as CSV, with an empty cell for an undefined value."""
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields, restval="")
        writer.writeheader()
        writer.writerows(_rounded(row) for row in rows)
    print(f"{path.name:22s} {len(rows):6,d} rows  {path.stat().st_size:>9,d} bytes")


def main() -> None:
    """Validate the corpus, run the sweep, and write both result files."""
    parser = argparse.ArgumentParser(description="Sweep detector thresholds.")
    parser.add_argument("--output-dir", type=Path, default=DEFAULT_OUTPUT_DIR)
    output_dir = parser.parse_args().output_dir

    check_labels(CORPUS, set(detector_names()))
    print(f"corpus: {len(CORPUS)} cases, {sum(c.is_positive for c in CORPUS)} positive")

    metrics, outcomes = sweep()
    output_dir.mkdir(parents=True, exist_ok=True)
    _write(output_dir / "sweep_metrics.csv", METRIC_FIELDS, metrics)
    _write(output_dir / "case_outcomes.csv", OUTCOME_FIELDS, outcomes)


if __name__ == "__main__":
    main()
