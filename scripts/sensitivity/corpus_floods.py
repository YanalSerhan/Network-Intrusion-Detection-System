"""
Volumetric cases: floods, and the busy hosts that look like victims of one.

Data Setup:  Nothing.
Data Input:  None.
Data Output: Labelled cases for the three flood detectors.

The flood detectors key on the *destination*, for the reason `counting` gives:
a flood is usually distributed, so no single source tally ever crosses a
threshold. The cost of that choice is the negatives below. A web server
accepting three hundred connections in ten seconds and a SYN flood aimed at it
produce the same per-destination count, and nothing in the packet header
separates them — which is why the busy-server case is the one that sets the
floor on how low the SYN threshold can usefully go.
"""

from typing import Any

from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.layers.l2 import Ether

from .case import Case, attack, benign
from .hosts import (
    EDGE_SERVER,
    EPHEMERAL_BASE,
    MONITOR,
    WORKSTATION,
    client_range,
)
from .timing import spread

FAMILY = "flood"

#: A port carrying no application protocol the parser recognises, so the UDP
#: cases are scored by the UDP flood detector alone.
OPAQUE_UDP_PORT = 9999


def _syn_burst(count: int, seconds: float, dst_port: int = 80) -> list[Any]:
    """Many distinct sources opening one connection each to one destination."""
    clients = client_range(count)
    return spread(
        [
            Ether()
            / IP(src=client, dst=EDGE_SERVER)
            / TCP(sport=EPHEMERAL_BASE + index, dport=dst_port, flags="S")
            for index, client in enumerate(clients)
        ],
        seconds,
    )


def _udp_burst(src: str, count: int, seconds: float) -> list[Any]:
    """One source pushing datagrams at one destination."""
    return spread(
        [
            Ether()
            / IP(src=src, dst=EDGE_SERVER)
            / UDP(sport=EPHEMERAL_BASE + index, dport=OPAQUE_UDP_PORT)
            for index in range(count)
        ],
        seconds,
    )


def _icmp_burst(src: str, count: int, seconds: float) -> list[Any]:
    """Echo requests from one source to one destination."""
    return spread(
        [Ether() / IP(src=src, dst=EDGE_SERVER) / ICMP() for _ in range(count)],
        seconds,
    )


def cases() -> list[Case]:
    """Return every volumetric case, positive and negative."""
    return [
        attack(
            "syn_flood_moderate",
            {"SynFloodDetector"},
            lambda: _syn_burst(150, 3.0),
            "A modest SYN flood, at the volume the shipped threshold targets.",
            FAMILY,
        ),
        attack(
            "syn_flood_heavy",
            {"SynFloodDetector"},
            lambda: _syn_burst(700, 2.0),
            "A flood no threshold in the sweep should miss.",
            FAMILY,
        ),
        attack(
            "udp_flood_moderate",
            {"UdpFloodDetector"},
            lambda: _udp_burst(client_range(1)[0], 250, 3.0),
            "A single-source UDP flood at the shipped threshold's volume.",
            FAMILY,
        ),
        attack(
            "udp_flood_heavy",
            {"UdpFloodDetector"},
            lambda: _udp_burst(client_range(1)[0], 900, 2.0),
            "A saturating UDP flood: the ceiling case, present so a threshold "
            "raised past the moderate flood can still be shown to catch something.",
            FAMILY,
        ),
        attack(
            "icmp_flood_moderate",
            {"IcmpFloodDetector"},
            lambda: _icmp_burst(client_range(1)[0], 60, 3.0),
            "A ping flood just over the shipped threshold.",
            FAMILY,
        ),
        attack(
            "icmp_flood_heavy",
            {"IcmpFloodDetector"},
            lambda: _icmp_burst(client_range(1)[0], 300, 2.0),
            "A ping flood an order of magnitude over it.",
            FAMILY,
        ),
        benign(
            "busy_web_server_300",
            lambda: _syn_burst(300, 10.0, dst_port=443),
            "Three hundred real clients connecting to one web server. Per "
            "destination this is identical to a distributed SYN flood, and it "
            "is what sets the floor under the SYN threshold.",
            FAMILY,
        ),
        benign(
            "voip_stream_400",
            lambda: _udp_burst(WORKSTATION, 400, 10.0),
            "An RTP media stream: sustained single-source UDP, at a rate no "
            "control-plane protocol reaches.",
            FAMILY,
        ),
        benign(
            "availability_ping_90",
            lambda: _icmp_burst(MONITOR, 90, 90.0),
            "A monitoring host pinging a server once a second. Low rate, high "
            "total — so a long window sees a flood where a short one does not.",
            FAMILY,
        ),
        benign(
            "traceroute_burst_30",
            lambda: _icmp_burst(WORKSTATION, 30, 3.0),
            "A traceroute: a short, sharp ICMP burst with a benign cause.",
            FAMILY,
        ),
    ]
