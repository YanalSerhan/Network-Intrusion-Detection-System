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

See docs/SENSITIVITY_ANALYSIS.md for the method.
"""

import argparse
import csv
from pathlib import Path

from sensitivity.analysis import SHIPPED_WINDOW, load_metrics
from sensitivity.proposal import PROPOSED_INTERVAL, PROPOSED_THRESHOLDS
from sensitivity.recommendation import best_common_window, recommended_thresholds
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

    metrics = load_metrics()
    window = best_common_window(metrics)
    rows = run(parsed, SHIPPED_WINDOW, {}, f"shipped — {SHIPPED_WINDOW:g}s interval")
    rows += run(
        parsed, window, recommended_thresholds(metrics, window),
        f"highest F1 — {window:g}s interval",
    )
    rows += run(
        parsed, PROPOSED_INTERVAL, PROPOSED_THRESHOLDS,
        f"proposed — {PROPOSED_INTERVAL:g}s interval",
    )

    path = output_dir / "alert_timeline.csv"
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=FIELDS)
        writer.writeheader()
        writer.writerows(rows)
    print(f"{path.name:22s} {len(rows):6,d} rows  {path.stat().st_size:>9,d} bytes")


if __name__ == "__main__":
    main()
