"""
Port-fanout cases: scans, and the benign traffic shaped like a scan.

Data Setup:  Nothing.
Data Input:  None.
Data Output: Labelled cases for the two breadth detectors.

Breadth over destination ports is the measurement, and the difficulty is that
three ordinary pieces of infrastructure produce it honestly: a load balancer
probing every service port on a backend, a monitoring agent taking a service
inventory, and any client opening several connections at once. The negatives
here are sized to land inside the range the positives occupy, because a corpus
whose benign cases all score zero cannot show a threshold costing anything.
"""

from typing import Any

from scapy.layers.inet import IP, TCP
from scapy.layers.l2 import Ether

from .case import Case, attack, benign
from .hosts import ATTACKER, EDGE_SERVER, LOAD_BALANCER, MONITOR, WORKSTATION
from .timing import spread

FAMILY = "recon"
BOTH_SCANS = {"TcpPortScanDetector", "SynScanDetector"}

#: Ports a load balancer or monitoring agent would legitimately probe.
SERVICE_PORTS = [22, 25, 53, 80, 110, 143, 443, 587, 993, 3306, 5432, 6379, 8080, 8443]


def _fanout(src: str, ports: list[int], flags: str, seconds: float) -> list[Any]:
    """
    One source touching a list of destination ports on one host.

    Args:
        src:     Source address.
        ports:   Destination ports, one packet each.
        flags:   TCP flag string — "S" for a half-open probe, "A" for an ACK scan.
        seconds: Span the burst occupies.

    Returns:
        Stamped packets.
    """
    return spread(
        [
            Ether() / IP(src=src, dst=EDGE_SERVER) / TCP(dport=port, flags=flags)
            for port in ports
        ],
        seconds,
    )


def cases() -> list[Case]:
    """Return every port-fanout case, positive and negative."""
    return [
        attack(
            "scan_stealth_12ports",
            BOTH_SCANS,
            lambda: _fanout(ATTACKER, list(range(1000, 1012)), "S", 120.0),
            "Low-and-slow scan: twelve ports over two minutes, which any "
            "window shorter than the scan cannot accumulate.",
            FAMILY,
        ),
        attack(
            "scan_moderate_25ports",
            BOTH_SCANS,
            lambda: _fanout(ATTACKER, list(range(1000, 1025)), "S", 20.0),
            "An unhurried scan at a rate a default configuration should catch.",
            FAMILY,
        ),
        attack(
            "scan_aggressive_60ports",
            BOTH_SCANS,
            lambda: _fanout(ATTACKER, list(range(1000, 1060)), "S", 3.0),
            "A loud scan: sixty ports in three seconds.",
            FAMILY,
        ),
        attack(
            "scan_ack_25ports",
            {"TcpPortScanDetector"},
            lambda: _fanout(ATTACKER, list(range(1000, 1025)), "A", 15.0),
            "An ACK scan maps firewall rules without a handshake. Breadth "
            "sees it; the SYN detector correctly does not, and firing there "
            "would mean the SYN filter had been weakened.",
            FAMILY,
        ),
        benign(
            "lb_backend_probe_10ports",
            lambda: _fanout(LOAD_BALANCER, SERVICE_PORTS[:10], "S", 30.0),
            "A load balancer health-checking ten services on one backend. "
            "Indistinguishable from a scan by breadth alone.",
            FAMILY,
        ),
        benign(
            "service_inventory_14ports",
            lambda: _fanout(MONITOR, SERVICE_PORTS, "S", 90.0),
            "A monitoring agent taking a service inventory — the widest "
            "honest fanout in the corpus, and the case that decides how low "
            "the port-scan threshold can go.",
            FAMILY,
        ),
        benign(
            "browser_session_4ports",
            lambda: _fanout(WORKSTATION, [80, 443, 8080, 8443], "S", 6.0),
            "A control: ordinary client behaviour, well below every threshold.",
            FAMILY,
        ),
    ]
