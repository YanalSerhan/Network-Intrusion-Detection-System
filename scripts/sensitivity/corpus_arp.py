"""
ARP cases: a poisoner keeping its mapping cached, and honest ARP chatter.

Data Setup:  Nothing.
Data Input:  None.
Data Output: Labelled cases for the ARP spoofing detector.

The detector counts ARP packets per claimed source rather than tracking which
MAC owns which address, which its own docstring is explicit about: it sees the
flood of gratuitous replies a poisoner sends, and misses one well-timed reply.
That makes its threshold unusually delicate — the honest ARP a host emits
after a lease renewal is only a few packets below the attack, so the two cases
here sit either side of a very narrow gap.
"""

from typing import Any

from scapy.layers.l2 import ARP, Ether

from .case import Case, attack, benign
from .hosts import EDGE_SERVER, WORKSTATION
from .timing import spread

FAMILY = "arp"

BROADCAST_MAC = "ff:ff:ff:ff:ff:ff"
SPOOFED_MAC = "de:ad:be:ef:00:01"
GATEWAY_IP = "192.168.1.1"


def _announcements(src_ip: str, src_mac: str, count: int, seconds: float) -> list[Any]:
    """Gratuitous ARP replies announcing ownership of an address."""
    return spread(
        [
            Ether(dst=BROADCAST_MAC)
            / ARP(op=2, psrc=src_ip, pdst=EDGE_SERVER, hwsrc=src_mac, hwdst=BROADCAST_MAC)
            for _ in range(count)
        ],
        seconds,
    )


def cases() -> list[Case]:
    """Return every ARP case, positive and negative."""
    return [
        attack(
            "arp_spoof_light_6",
            {"ArpSpoofingDetector"},
            lambda: _announcements(GATEWAY_IP, SPOOFED_MAC, 6, 20.0),
            "Six gratuitous replies claiming the gateway — enough to keep a "
            "poisoned mapping cached, and barely over the threshold.",
            FAMILY,
        ),
        attack(
            "arp_spoof_heavy_30",
            {"ArpSpoofingDetector"},
            lambda: _announcements(GATEWAY_IP, SPOOFED_MAC, 30, 10.0),
            "A poisoner refreshing its claim aggressively.",
            FAMILY,
        ),
        benign(
            "arp_housekeeping_9",
            lambda: _announcements(WORKSTATION, "02:00:00:00:00:09", 9, 30.0),
            "Duplicate-address detection and gateway resolution after a lease "
            "renewal: nine ARP packets from one host, nothing poisoned.",
            FAMILY,
        ),
    ]
