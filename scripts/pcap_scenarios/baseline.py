"""Ordinary traffic, which must produce no alerts at all."""

from typing import Any

from scapy.layers.dns import DNS, DNSQR
from scapy.layers.http import HTTP, HTTPRequest
from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.layers.l2 import Ether

from .common import INTERNAL_HOST_IP, at_intervals


def benign() -> list[Any]:
    """
    A DNS lookup, a page load, a TLS connection and a ping.

    A detection suite that only ever replays attacks cannot tell a working
    detector from one that fires on everything, so this file is as much a
    part of the fixture set as the attacks are.
    """
    packets = [
        Ether()
        / IP(src=INTERNAL_HOST_IP, dst="8.8.8.8")
        / UDP(sport=40001, dport=53)
        / DNS(rd=1, qd=DNSQR(qname="www.example.com", qtype=1)),
        Ether()
        / IP(src=INTERNAL_HOST_IP, dst="93.184.216.34")
        / TCP(sport=40002, dport=80)
        / HTTP()
        / HTTPRequest(Method=b"GET", Path=b"/index.html", Host=b"www.example.com"),
        Ether() / IP(src=INTERNAL_HOST_IP, dst="93.184.216.34") / TCP(sport=40003, dport=443),
        Ether() / IP(src="192.168.1.51", dst=INTERNAL_HOST_IP) / ICMP(),
    ]
    return at_intervals(packets, step=2.0, jitter=1.0)
