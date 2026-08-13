"""Volume-based scenarios: floods and ARP abuse."""

from typing import Any

from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.layers.l2 import ARP, Ether

from .common import ATTACKER_IP, VICTIM_IP, at_intervals

#: A gratuitous ARP is announced to the whole segment, not to one host.
BROADCAST_MAC = "ff:ff:ff:ff:ff:ff"

#: The attacker's MAC, claiming the gateway's address.
SPOOFED_MAC = "de:ad:be:ef:00:01"


def syn_flood() -> list[Any]:
    """
    150 SYNs at a single port: a flood, and deliberately not a scan.

    Jittered for the same reason as the port scan — a fixed interval to one
    destination would also satisfy the beaconing detector.
    """
    return at_intervals(
        [
            Ether() / IP(src=ATTACKER_IP, dst=VICTIM_IP) / TCP(sport=40000 + i, dport=80, flags="S")
            for i in range(150)
        ],
        step=0.002,
        jitter=0.006,
    )


def udp_flood() -> list[Any]:
    """250 datagrams at a non-DNS port, so only the UDP flood detector sees them."""
    return at_intervals(
        [
            Ether() / IP(src=ATTACKER_IP, dst=VICTIM_IP) / UDP(sport=40000 + i, dport=9999)
            for i in range(250)
        ]
    )


def icmp_flood() -> list[Any]:
    """60 echo requests, over the ICMP flood threshold of 50."""
    return at_intervals(
        [Ether() / IP(src=ATTACKER_IP, dst=VICTIM_IP) / ICMP() for _ in range(60)]
    )


def arp_spoofing() -> list[Any]:
    """8 gratuitous ARP replies claiming the gateway's address."""
    return at_intervals(
        [
            Ether(dst=BROADCAST_MAC)
            / ARP(
                op=2,
                psrc="192.168.1.1",
                pdst=VICTIM_IP,
                hwsrc=SPOOFED_MAC,
                hwdst=BROADCAST_MAC,
            )
            for _ in range(8)
        ]
    )
