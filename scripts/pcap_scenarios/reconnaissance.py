"""Scenarios where an attacker is mapping the network before acting."""

from typing import Any

from scapy.layers.inet import IP, TCP
from scapy.layers.l2 import Ether

from .common import ATTACKER_IP, VICTIM_IP, at_intervals


def tcp_port_scan() -> list[Any]:
    """
    40 SYNs across 40 ports from one source.

    Crosses both the port-scan threshold (15 unique ports) and the SYN-scan
    threshold (10), which is correct: a half-open scan is a port scan.

    Jittered so the run does not also read as a beacon: 40 packets to one
    destination at a fixed interval is exactly the pattern the beaconing
    detector looks for.
    """
    return at_intervals(
        [
            Ether() / IP(src=ATTACKER_IP, dst=VICTIM_IP) / TCP(dport=port, flags="S")
            for port in range(1000, 1040)
        ],
        step=0.05,
        jitter=0.1,
    )
