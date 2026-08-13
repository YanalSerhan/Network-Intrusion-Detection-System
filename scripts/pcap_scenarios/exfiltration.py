"""Scenarios where an attacker already inside is moving or removing data."""

from typing import Any

from scapy.layers.inet import IP, TCP
from scapy.layers.l2 import Ether

from .common import (
    BULK_PAYLOAD,
    EXFIL_DESTINATION_IP,
    INTERNAL_HOST_IP,
    at_intervals,
)


def data_exfiltration() -> list[Any]:
    """
    40 full-size outbound packets from one internal host.

    The shipped threshold is 50 MB, which would mean a 50 MB fixture in the
    repository. The scenario keeps the shape — one host pushing bulk data to
    one external address — and the end-to-end test lowers the threshold
    rather than the fixture growing to meet it.
    """
    return at_intervals(
        [
            Ether()
            / IP(src=INTERNAL_HOST_IP, dst=EXFIL_DESTINATION_IP)
            / TCP(sport=40000 + i, dport=443)
            / BULK_PAYLOAD
            for i in range(40)
        ],
        step=0.1,
        jitter=0.05,
    )


def lateral_movement() -> list[Any]:
    """One internal host reaching 25 other internal hosts over SMB."""
    return at_intervals(
        [
            Ether() / IP(src=INTERNAL_HOST_IP, dst=f"192.168.1.{host}") / TCP(dport=445)
            for host in range(100, 125)
        ],
        step=0.5,
        jitter=0.3,
    )
