"""Scenarios where an attacker is guessing credentials."""

from typing import Any

from scapy.layers.http import HTTP, HTTPRequest
from scapy.layers.inet import IP, TCP
from scapy.layers.l2 import Ether

from .common import ATTACKER_IP, VICTIM_IP, at_intervals


def ssh_brute_force() -> list[Any]:
    """
    15 SSH connection attempts from one source, over the threshold of 10.

    Jittered widely enough that the interval variance stays clear of the
    beaconing tolerance; a scripted login loop is not a C2 beacon.
    """
    return at_intervals(
        [
            Ether() / IP(src=ATTACKER_IP, dst=VICTIM_IP) / TCP(sport=40000 + i, dport=22, flags="S")
            for i in range(15)
        ],
        step=0.5,
        jitter=1.0,
    )


def http_brute_force() -> list[Any]:
    """
    25 POSTs to a login endpoint.

    Jittered on purpose: a perfectly regular request every second is also a
    beacon, and this scenario should raise exactly one kind of alert.
    """
    return at_intervals(
        [
            Ether()
            / IP(src=ATTACKER_IP, dst=VICTIM_IP)
            / TCP(sport=40000 + i, dport=80)
            / HTTP()
            / HTTPRequest(Method=b"POST", Path=b"/admin/login", Host=b"victim.example")
            for i in range(25)
        ],
        step=1.0,
        jitter=0.6,
    )
