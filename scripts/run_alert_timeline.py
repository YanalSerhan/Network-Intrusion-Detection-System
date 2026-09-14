"""
Replay a composed half-hour of traffic and record when alerts surface.

Data Setup:  None; the timeline is generated from a fixed seed.
Data Input:  An optional output directory (defaults to research/).
Data Output: alert_timeline.csv — one row per alert.

Usage:
    uv run python scripts/run_alert_timeline.py [--output-dir DIR]

Three configurations are replayed against the same packets, so the difference
in the resulting chart is the configuration and nothing else: what ships
today, the point the sweep scores highest, and the one this analysis actually
proposes. The middle one is included because it is the obvious reading of the
sweep and it is wrong — seeing its alert volume is the argument.

All three run at the same evaluation interval. Since Milestone 21 that is not
a detection parameter, so varying it here would only vary how late each alert
appeared.

See docs/SENSITIVITY_ANALYSIS.md for the method.
"""

import argparse
import csv
from pathlib import Path
from typing import Any

from sensitivity.analysis import load_metrics
from sensitivity.grid import THRESHOLDS
from sensitivity.proposal import PREVIOUS_THRESHOLDS, PROPOSED_INTERVAL
from sensitivity.recommendation import best_f1_points
from sensitivity.scenario import DURATION, compose
from sensitivity.timeline import run

from network_defender.parser.parser import PacketParser

DEFAULT_OUTPUT_DIR = Path(__file__).resolve().parent.parent / "research"
FIELDS = ["config", "raised_at", "detector", "attributable"]


def main() -> None:
    """Compose the timeline, replay both configurations, write the rows."""
    parser = argparse.ArgumentParser(description="Replay the alert-volume timeline.")
    parser.add_argument("--output-dir", type=Path, default=DEFAULT_OUTPUT_DIR)
    output_dir = parser.parse_args().output_dir
    output_dir.mkdir(parents=True, exist_ok=True)

    packet_parser = PacketParser()
    packet_parser.start()
    parsed = [
        packet
        for packet in (packet_parser.parse_safe(raw) for raw in compose())
        if packet is not None
    ]
    print(f"timeline: {len(parsed):,} packets over {DURATION:g}s")

    best = best_f1_points(load_metrics())
    highest_f1 = {
        str(detector): {
            THRESHOLDS[str(detector)][0]: int(row["threshold"]),
            "time_window_seconds": int(row["window_seconds"]),
        }
        for detector, row in best.iterrows()
        if str(detector) in THRESHOLDS
    }
    def by_threshold(values: dict[str, int]) -> dict[str, dict[str, Any]]:
        return {name: {THRESHOLDS[name][0]: value} for name, value in values.items()}

    # The recommendation is already in config/detectors.json, so "recommended"
    # is the empty override and the *previous* thresholds are the ones that
    # have to be named explicitly.
    rows = run(parsed, PROPOSED_INTERVAL, by_threshold(PREVIOUS_THRESHOLDS), "previous thresholds")
    rows += run(parsed, PROPOSED_INTERVAL, highest_f1, "highest F1")
    rows += run(parsed, PROPOSED_INTERVAL, {}, "recommended")

    path = output_dir / "alert_timeline.csv"
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=FIELDS)
        writer.writeheader()
        writer.writerows(rows)
    print(f"{path.name:22s} {len(rows):6,d} rows  {path.stat().st_size:>9,d} bytes")


if __name__ == "__main__":
    main()
