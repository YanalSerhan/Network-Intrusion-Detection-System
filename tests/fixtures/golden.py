"""
Golden-file support: run a capture through the detectors and normalise it.

Data Setup:  The committed captures in tests/data/pcaps.
Data Input:  A scenario name.
Data Output: A JSON-serialisable dict of everything the detectors produced.

The detection service is driven directly rather than through the SDK: no
database, no threads, no clock. Everything volatile — alert IDs, wall-clock
timestamps, ordering by dict insertion — is stripped or sorted away, so a
diff against the stored file means a detector's *output* changed, which is
the only thing a golden file is any good at catching.
"""

import json
import os
from pathlib import Path
from typing import Any

from scapy.utils import rdpcap

from network_defender.parser.parser import PacketParser
from network_defender.services.detection import DetectionService
from network_defender.shared.paths import PROJECT_ROOT

from .pcaps import GOLDEN_DIR, sample_pcap

#: Set to 1 to rewrite the golden files from the current behaviour. Every
#: rewritten file must be reviewed in the diff before it is committed — an
#: unexamined refresh turns a regression test into a rubber stamp.
REFRESH_ENV_VAR = "ND_REFRESH_GOLDEN"


def refresh_requested() -> bool:
    """Return True when the run should rewrite golden files instead of asserting."""
    return os.environ.get(REFRESH_ENV_VAR) == "1"


def _normalise(detection: Any) -> dict[str, Any]:
    """Reduce a DetectionAlert to the fields that should never drift."""
    return {
        "detector": detection.detector_name,
        "severity": str(detection.severity),
        "tactic": str(detection.tactic) if detection.tactic else None,
        "src_ip": detection.src_ip,
        "dst_ip": detection.dst_ip,
        "description": detection.description,
        "evidence": detection.evidence,
    }


def detections_for(scenario: str) -> dict[str, Any]:
    """
    Replay one capture through the real detectors and return the result.

    Args:
        scenario: Capture name, e.g. "tcp_port_scan".

    Returns:
        A dict with the packet count and every detection, sorted so the
        output does not depend on dictionary iteration order.
    """
    service = DetectionService(config_dir=PROJECT_ROOT / "config")
    service.registry.load_detectors()
    parser = PacketParser()
    parser.start()

    processed = 0
    for packet in rdpcap(str(sample_pcap(scenario))):
        parsed = parser.parse_safe(packet)
        if parsed is not None:
            service.process_packet(parsed)
            processed += 1

    detections = [_normalise(d) for d in service.evaluate_detectors()]
    detections.sort(key=lambda d: (d["detector"], d["src_ip"] or "", d["dst_ip"] or ""))
    return {"scenario": scenario, "packets": processed, "detections": detections}


def golden_path(scenario: str) -> Path:
    """Return the path of the stored expectation for a scenario."""
    return GOLDEN_DIR / f"{scenario}.json"


def load_golden(scenario: str) -> dict[str, Any]:
    """
    Read the stored expectation for a scenario.

    Args:
        scenario: Capture name.

    Returns:
        The parsed golden file.

    Raises:
        FileNotFoundError: With the command needed to create it.
    """
    path = golden_path(scenario)
    if not path.exists():
        raise FileNotFoundError(
            f"No golden file at '{path}'. Create it with: "
            f"{REFRESH_ENV_VAR}=1 uv run pytest tests/e2e/test_golden_detections.py"
        )
    return dict(json.loads(path.read_text()))


def write_golden(scenario: str, payload: dict[str, Any]) -> None:
    """Write a scenario's expectation to disk, formatted for readable diffs."""
    GOLDEN_DIR.mkdir(parents=True, exist_ok=True)
    golden_path(scenario).write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n")
