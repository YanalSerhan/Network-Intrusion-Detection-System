"""
PCAP fixtures for tests that drive the pipeline from a capture file.

Data Setup:  Packets are synthesised with Scapy and written to a file under
             the test's ``tmp_path``.
Data Input:  None — each fixture is one named traffic scenario.
Data Output: A path to a .pcap file.

Replaying a file is how a test exercises the real capture path without a
network interface or elevated privileges: the replay code deliberately reuses
the live packet callback, so what the detectors see here is what they would
see on the wire.
"""

from collections.abc import Iterator
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from scapy.layers.inet import IP, TCP
from scapy.layers.l2 import Ether
from scapy.utils import wrpcap

from network_defender.sdk.sdk import NetworkDefenderSDK

from .constants import PUBLIC_IP

#: Enough distinct destination ports to clear the port-scan threshold in
#: config/detectors.json with room to spare.
SCAN_PORT_RANGE = range(1000, 1040)

#: The host being scanned in the fixtures below.
SCAN_TARGET_IP = "192.168.1.10"


@pytest.fixture()
def scan_pcap(tmp_path: Path) -> Path:
    """A 40-port SYN scan from a routable source address."""
    path = tmp_path / "scan.pcap"
    wrpcap(
        str(path),
        [
            Ether() / IP(src=PUBLIC_IP, dst=SCAN_TARGET_IP) / TCP(dport=port, flags="S")
            for port in SCAN_PORT_RANGE
        ],
    )
    return path


#: The committed attack captures, one file per scenario. Regenerate with
#: `uv run python scripts/generate_test_pcaps.py`.
SAMPLE_PCAP_DIR = Path(__file__).resolve().parents[1] / "data" / "pcaps"

#: Expected detector output for those captures, for regression comparison.
GOLDEN_DIR = Path(__file__).resolve().parents[1] / "data" / "golden"


def sample_pcap(name: str) -> Path:
    """
    Return the path to a committed sample capture.

    Args:
        name: Scenario name, matching a key of ``scripts.pcap_scenarios``.

    Returns:
        Path to ``tests/data/pcaps/<name>.pcap``.

    Raises:
        FileNotFoundError: If the capture is missing, which means the
            generator and the suite have drifted apart.
    """
    path = SAMPLE_PCAP_DIR / f"{name}.pcap"
    if not path.exists():
        raise FileNotFoundError(
            f"Missing sample capture '{path}'. "
            f"Regenerate with: uv run python scripts/generate_test_pcaps.py"
        )
    return path


@pytest.fixture()
def running_sdk(sdk: NetworkDefenderSDK) -> Iterator[NetworkDefenderSDK]:
    """
    A fully started SDK with the live sniffer stubbed out.

    Capture is the only service that needs a privileged socket, and PCAP
    replay does not go near it — but ``start()`` opens one regardless, so the
    sniffer is patched rather than the lifecycle being worked around.
    """
    with patch("network_defender.capture.service.AsyncSniffer") as sniffer:
        sniffer.return_value = MagicMock()
        sdk.start()
        try:
            yield sdk
        finally:
            sdk.stop()
