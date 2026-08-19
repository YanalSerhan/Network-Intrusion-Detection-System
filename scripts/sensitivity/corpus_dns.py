"""
DNS cases: tunnelled payload, and the encoded lookups that resemble it.

Data Setup:  A seeded RNG, so every generated label is reproducible.
Data Input:  None.
Data Output: Labelled cases for the DNS tunnelling detector.

The detector requires volume *and* a majority of high-entropy names, and its
docstring gives the reason: volume alone flags a busy resolver, entropy alone
flags the random subdomains CDNs generate. Both claims are testable, so both
have a negative case here — a resolver carrying three hundred ordinary
lookups, and an endpoint agent doing base32-encoded reputation lookups, which
is a real product behaviour and is not distinguishable from a tunnel by
entropy at all.
"""

import random
from typing import Any

from pcap_scenarios.common import RANDOM_SEED
from scapy.layers.dns import DNS, DNSQR
from scapy.layers.inet import IP, UDP
from scapy.layers.l2 import Ether

from .case import Case, attack, benign
from .hosts import COMPROMISED_HOST, EPHEMERAL_BASE, PUBLIC_RESOLVER, WORKSTATION
from .timing import spread

FAMILY = "dns"

DNS_PORT = 53
ENCODED_ALPHABET = "abcdefghijklmnopqrstuvwxyz0123456789"
HEX_ALPHABET = "0123456789abcdef"

#: Long enough that the entropy estimate is stable and that the fixed suffix
#: does not dilute it below the threshold, and inside the 63-octet label limit.
TUNNEL_LABEL_LENGTH = 55

#: A CDN's cache key is much shorter, which is most of why its entropy per
#: character comes out lower once the fixed suffix is included.
CDN_LABEL_LENGTH = 16

ORDINARY_NAMES = [
    "www.example.com",
    "api.example.com",
    "mail.example.org",
    "updates.example.net",
    "docs.example.com",
]


def _queries(src: str, names: list[str], seconds: float) -> list[Any]:
    """One source resolving a list of names."""
    return spread(
        [
            Ether()
            / IP(src=src, dst=PUBLIC_RESOLVER)
            / UDP(sport=EPHEMERAL_BASE + index, dport=DNS_PORT)
            / DNS(rd=1, qd=DNSQR(qname=name, qtype=1))
            for index, name in enumerate(names)
        ],
        seconds,
    )


def _encoded(count: int, length: int, alphabet: str, suffix: str) -> list[str]:
    """Generate `count` names whose leading label is encoded payload."""
    rng = random.Random(RANDOM_SEED)
    return [
        "".join(rng.choice(alphabet) for _ in range(length)) + suffix for _ in range(count)
    ]


def cases() -> list[Case]:
    """Return every DNS case, positive and negative."""
    return [
        attack(
            "dns_tunnel_30q",
            {"DnsTunnelingDetector"},
            lambda: _queries(
                COMPROMISED_HOST,
                _encoded(30, TUNNEL_LABEL_LENGTH, ENCODED_ALPHABET, ".tunnel.example"),
                60.0,
            ),
            "A tunnel kept quiet: thirty queries a minute, under the shipped "
            "threshold of fifty.",
            FAMILY,
        ),
        attack(
            "dns_tunnel_120q",
            {"DnsTunnelingDetector"},
            lambda: _queries(
                COMPROMISED_HOST,
                _encoded(120, TUNNEL_LABEL_LENGTH, ENCODED_ALPHABET, ".tunnel.example"),
                60.0,
            ),
            "A tunnel moving real data, at two queries a second.",
            FAMILY,
        ),
        benign(
            "cdn_cache_keys_60q",
            lambda: _queries(
                WORKSTATION,
                _encoded(60, CDN_LABEL_LENGTH, HEX_ALPHABET, ".cdn.example"),
                60.0,
            ),
            "Machine-generated CDN hostnames: random, but hexadecimal and "
            "short, so the entropy per character stays under the threshold.",
            FAMILY,
        ),
        benign(
            "reputation_lookups_80q",
            lambda: _queries(
                WORKSTATION,
                _encoded(80, TUNNEL_LABEL_LENGTH, ENCODED_ALPHABET, ".rep.example"),
                60.0,
            ),
            "An endpoint agent doing encoded reputation lookups. Byte for "
            "byte the same shape as the tunnel above — the hardest negative "
            "in the corpus, and one the detector has no way to pass.",
            FAMILY,
        ),
        benign(
            "resolver_busy_300q",
            lambda: _queries(WORKSTATION, ORDINARY_NAMES * 60, 20.0),
            "Three hundred ordinary lookups in twenty seconds: well over "
            "every query-count threshold, and saved only by the entropy test.",
            FAMILY,
        ),
    ]
