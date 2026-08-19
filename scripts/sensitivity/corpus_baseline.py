"""
Ordinary traffic, and the one detector with no numeric threshold.

Data Setup:  Nothing.
Data Input:  None.
Data Output: Labelled cases with no attack shape at all.

`SuspiciousPortDetector` is here rather than in the sweep because it has no
threshold to sweep: it matches a port list an analyst edits, so its operating
point is a set, not a number. Its two cases still earn their place — they are
what the default-configuration table reports it against, and the IRC case is a
reminder that "suspicious port" is a statement about a site's policy rather
than about the packet.
"""

from typing import Any

from pcap_scenarios.baseline import benign as ordinary_traffic
from scapy.layers.inet import IP, TCP
from scapy.layers.l2 import Ether

from .case import Case, attack, benign
from .hosts import C2_SERVER, COMPROMISED_HOST, WORKSTATION
from .timing import spread

FAMILY = "baseline"

BACKDOOR_PORT = 4444
IRC_PORT = 6667


def _connections(src: str, dst: str, port: int, count: int, seconds: float) -> list[Any]:
    """A handful of connections to one destination port."""
    return spread(
        [Ether() / IP(src=src, dst=dst) / TCP(dport=port, flags="S") for _ in range(count)],
        seconds,
    )


def cases() -> list[Case]:
    """Return the baseline cases, positive and negative."""
    return [
        attack(
            "backdoor_port_4444",
            {"SuspiciousPortDetector"},
            lambda: _connections(COMPROMISED_HOST, C2_SERVER, BACKDOOR_PORT, 3, 30.0),
            "Three connections to a port associated with backdoor tooling.",
            FAMILY,
        ),
        benign(
            "irc_client_6667",
            lambda: _connections(WORKSTATION, C2_SERVER, IRC_PORT, 2, 30.0),
            "An IRC client on the default port. On the shipped list, so this "
            "is an unavoidable false positive until the list is edited — "
            "which is what makes the list a policy decision.",
            FAMILY,
        ),
        benign(
            "ordinary_traffic",
            ordinary_traffic,
            "A DNS lookup, a page load, a TLS connection and a ping, reused "
            "from the golden fixtures. Anything firing here is firing on "
            "nothing at all.",
            FAMILY,
        ),
    ]
