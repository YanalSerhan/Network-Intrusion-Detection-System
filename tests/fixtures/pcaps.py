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

from pathlib import Path

import pytest
from scapy.layers.inet import IP, TCP
from scapy.layers.l2 import Ether
from scapy.utils import wrpcap

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
