"""
Regenerate the synthetic attack PCAPs the end-to-end suite replays.

Data Setup:  None — the scenarios are self-contained.
Data Input:  An optional output directory (defaults to tests/data/pcaps).
Data Output: One .pcap per scenario, plus a printed summary.

Usage:
    uv run python scripts/generate_test_pcaps.py [--output-dir DIR]

The files are committed rather than generated at test time so a change in
Scapy's defaults shows up as a diff to review instead of as traffic that
quietly stopped resembling the attack it is named after.
"""

import argparse
from pathlib import Path

from pcap_scenarios import SCENARIOS
from scapy.utils import wrpcap

DEFAULT_OUTPUT_DIR = Path(__file__).resolve().parent.parent / "tests" / "data" / "pcaps"


def generate(output_dir: Path) -> None:
    """
    Write one PCAP per scenario into the given directory.

    Args:
        output_dir: Destination directory, created if it does not exist.
    """
    output_dir.mkdir(parents=True, exist_ok=True)
    for name, build in SCENARIOS.items():
        packets = build()
        path = output_dir / f"{name}.pcap"
        wrpcap(str(path), packets)
        print(f"{name:20s} {len(packets):4d} packets  {path.stat().st_size:>8,d} bytes")


def main() -> None:
    """Parse arguments and regenerate every scenario."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", type=Path, default=DEFAULT_OUTPUT_DIR)
    generate(parser.parse_args().output_dir)


if __name__ == "__main__":
    main()
