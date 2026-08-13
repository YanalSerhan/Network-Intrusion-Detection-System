"""
End-to-end: bulk outbound transfer, on a threshold a fixture can reach.

The shipped exfiltration threshold is 50 MB of outbound traffic per window.
Committing a 50 MB capture to make a test cross it would trade a real cost —
clone size, CI time — for no extra confidence: the detector sums packet
lengths, so the only thing a bigger file proves is that addition still works.

So the capture keeps the shape of the attack (one internal host pushing bulk
data to one external address) and the test lowers the threshold to meet it,
through the same detectors.json the deployment reads. That the override is
picked up at all is itself part of what this exercises.
"""

import json
import shutil
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from network_defender.constants import MitreTactic, Severity
from network_defender.sdk.sdk import NetworkDefenderSDK
from network_defender.shared.config_models import AppConfig, CaptureConfig
from network_defender.shared.paths import PROJECT_ROOT
from network_defender.shared.rate_limit_models import RateLimitConfig
from tests.fixtures.pcaps import sample_pcap

#: Below the ~56 KB the capture carries, so the detector fires; far enough
#: above zero that an empty window still cannot trip it.
LOWERED_BYTES_THRESHOLD = 40_000


@pytest.fixture()
def exfiltration_config_dir(tmp_path: Path) -> Path:
    """A copy of the shipped config with only the exfiltration limit changed."""
    config_dir = tmp_path / "config"
    shutil.copytree(PROJECT_ROOT / "config", config_dir)

    detectors_path = config_dir / "detectors.json"
    detectors = json.loads(detectors_path.read_text())
    detectors["DataExfiltrationDetector"]["bytes_out_threshold"] = LOWERED_BYTES_THRESHOLD
    detectors_path.write_text(json.dumps(detectors, indent=2))
    return config_dir


def test_bulk_outbound_transfer_raises_an_exfiltration_alert(
    exfiltration_config_dir: Path,
) -> None:
    """One host pushing bulk data outbound is the finding, at any threshold."""
    sdk = NetworkDefenderSDK(
        app_config=AppConfig(
            capture=CaptureConfig(interface="eth0", max_packets_per_second=0),
            config_dir=str(exfiltration_config_dir),
        ),
        rate_limit_config=RateLimitConfig(services={}),
    )
    with patch("network_defender.capture.service.AsyncSniffer") as sniffer:
        sniffer.return_value = MagicMock()
        sdk.start()
        try:
            sdk.start_capture_from_pcap(sample_pcap("data_exfiltration"))
            sdk._detection_service.evaluate_detectors()

            alert = next(
                a for a in sdk.list_alerts() if a.rule_triggered == "DataExfiltrationDetector"
            )
            assert alert.severity is Severity.CRITICAL
            assert alert.tactic is MitreTactic.EXFILTRATION
            assert alert.evidence["bytes_out"] >= LOWERED_BYTES_THRESHOLD
        finally:
            sdk.stop()


def test_the_shipped_threshold_does_not_fire_on_the_same_traffic(
    running_sdk: NetworkDefenderSDK,
) -> None:
    """56 KB is not exfiltration, and the default configuration must agree."""
    running_sdk.start_capture_from_pcap(sample_pcap("data_exfiltration"))
    running_sdk._detection_service.evaluate_detectors()

    assert not [
        a for a in running_sdk.list_alerts() if a.rule_triggered == "DataExfiltrationDetector"
    ]
