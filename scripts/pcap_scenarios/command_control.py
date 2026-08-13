"""Scenarios where a compromised host is talking to its operator."""

import random
from typing import Any

from scapy.layers.dns import DNS, DNSQR
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.l2 import Ether

from .common import (
    EXFIL_DESTINATION_IP,
    INTERNAL_HOST_IP,
    RANDOM_SEED,
    at_intervals,
)

#: Label alphabet for tunnelled queries. Encoded payload looks like this:
#: uniformly distributed over the character set, which is what pushes Shannon
#: entropy past the detector's 4.5-bit threshold.
_LABEL_ALPHABET = "abcdefghijklmnopqrstuvwxyz0123456789"

#: Long enough that the entropy estimate is stable, short enough to stay
#: inside the 63-octet DNS label limit.
_LABEL_LENGTH = 45


def dns_tunneling() -> list[Any]:
    """60 queries whose labels carry encoded payload rather than a hostname."""
    rng = random.Random(RANDOM_SEED)
    names = [
        "".join(rng.choice(_LABEL_ALPHABET) for _ in range(_LABEL_LENGTH)) + ".tunnel.example"
        for _ in range(60)
    ]
    return at_intervals(
        [
            Ether()
            / IP(src=INTERNAL_HOST_IP, dst="8.8.8.8")
            / UDP(sport=40000 + i, dport=53)
            / DNS(rd=1, qd=DNSQR(qname=name, qtype=1))
            for i, name in enumerate(names)
        ]
    )


def beaconing() -> list[Any]:
    """15 connections to one destination at an exact 60-second cadence."""
    return at_intervals(
        [
            Ether() / IP(src=INTERNAL_HOST_IP, dst=EXFIL_DESTINATION_IP) / TCP(dport=443)
            for _ in range(15)
        ],
        step=60.0,
    )


def suspicious_port() -> list[Any]:
    """Three packets to a port associated with backdoor tooling."""
    return at_intervals(
        [
            Ether() / IP(src=INTERNAL_HOST_IP, dst=EXFIL_DESTINATION_IP) / TCP(dport=4444)
            for _ in range(3)
        ]
    )
