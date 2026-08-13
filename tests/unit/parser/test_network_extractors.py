"""Tests for extracting addresses from the network layer."""

from scapy.layers.inet import IP, TCP
from scapy.layers.inet6 import IPv6
from scapy.layers.l2 import ARP, Ether

from network_defender.parser.extractors import (
    extract_ip_addresses,
)
from tests.fixtures.packets import stamped

# ---------------------------------------------------------------------------
# extract_ip_addresses
# ---------------------------------------------------------------------------


def test_extract_ip_ipv4() -> None:
    pkt = stamped(Ether() / IP(src="1.2.3.4", dst="5.6.7.8") / TCP())
    src, dst = extract_ip_addresses(pkt)  # type: ignore[arg-type]
    assert src == "1.2.3.4"
    assert dst == "5.6.7.8"


def test_extract_ip_ipv6() -> None:
    pkt = stamped(Ether() / IPv6(src="::1", dst="::2") / TCP())
    src, dst = extract_ip_addresses(pkt)  # type: ignore[arg-type]
    assert src == "::1"
    assert dst == "::2"


def test_extract_ip_arp() -> None:
    pkt = stamped(Ether() / ARP(psrc="10.0.0.1", pdst="10.0.0.2"))
    src, dst = extract_ip_addresses(pkt)  # type: ignore[arg-type]
    assert src == "10.0.0.1"
    assert dst == "10.0.0.2"


def test_extract_ip_no_ip_layer() -> None:
    pkt = stamped(Ether())
    src, dst = extract_ip_addresses(pkt)  # type: ignore[arg-type]
    assert src is None
    assert dst is None
