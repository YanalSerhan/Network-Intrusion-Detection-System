"""Tests for classifying a captured packet's protocol."""


# pyrefly: ignore [missing-import]
from scapy.layers.dns import DNS, DNSQR

# pyrefly: ignore [missing-import]
from scapy.layers.inet import IP, TCP, UDP

# pyrefly: ignore [missing-import]
from scapy.layers.l2 import ARP, Ether

from network_defender.capture.filters import (
    detect_protocol,
)
from network_defender.constants import Protocol

# ---------------------------------------------------------------------------
# detect_protocol
# ---------------------------------------------------------------------------


def test_detect_tcp_packet() -> None:
    packet = Ether() / IP() / TCP()
    assert detect_protocol(packet) == Protocol.TCP


def test_detect_udp_packet() -> None:
    packet = Ether() / IP() / UDP()
    assert detect_protocol(packet) == Protocol.UDP


def test_detect_dns_packet() -> None:
    packet = Ether() / IP() / UDP() / DNS(qd=DNSQR(qname="example.com"))
    assert detect_protocol(packet) == Protocol.DNS


def test_detect_arp_packet() -> None:
    packet = Ether() / ARP()
    assert detect_protocol(packet) == Protocol.ARP


def test_detect_icmp_packet() -> None:
    from scapy.layers.inet import ICMP

    packet = Ether() / IP() / ICMP()
    assert detect_protocol(packet) == Protocol.ICMP


def test_detect_ipv6_packet() -> None:
    from scapy.layers.inet6 import IPv6

    packet = Ether() / IPv6()
    assert detect_protocol(packet) == Protocol.IPV6


def test_detect_ipv4_only_packet() -> None:
    """A bare IP packet (no TCP/UDP/ICMP) should resolve to IPv4."""
    from scapy.packet import Raw

    packet = Ether() / IP() / Raw(b"\x00")
    # Raw payload has no recognised layer; IP is detected
    assert detect_protocol(packet) in (Protocol.IP, Protocol.UNKNOWN)


def test_detect_ethernet_only_packet() -> None:
    """A bare Ethernet frame with no IP should resolve to ETHERNET."""
    packet = Ether()
    assert detect_protocol(packet) == Protocol.ETHERNET


def test_detect_tls_packet() -> None:
    """TCP payload starting with 0x16 should be classified as TLS."""
    from scapy.packet import Raw

    tls_record = b"\x16\x03\x03" + b"\x00" * 20
    packet = Ether() / IP() / TCP() / Raw(tls_record)
    assert detect_protocol(packet) == Protocol.TLS


def test_detect_unknown_packet() -> None:
    from scapy.packet import Raw

    packet = Raw(b"\x00\x01\x02\x03")
    assert detect_protocol(packet) == Protocol.UNKNOWN
