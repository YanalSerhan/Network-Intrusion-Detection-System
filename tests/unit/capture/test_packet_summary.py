"""Tests that a captured packet is summarised into the right protocol and fields."""

from datetime import UTC

from scapy.layers.dns import DNS, DNSQR
from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.layers.inet6 import IPv6
from scapy.layers.l2 import ARP, Ether

from network_defender.capture.packet_summary import summarise_packet
from network_defender.constants import Protocol

# ---------------------------------------------------------------------------
# TCP
# ---------------------------------------------------------------------------


def test_summarise_tcp_sets_protocol_and_ports() -> None:
    pkt = Ether() / IP(src="1.2.3.4", dst="5.6.7.8") / TCP(sport=12345, dport=80)
    pkt.time = 1_700_000_000.0
    summary = summarise_packet(pkt)
    assert summary.protocol == Protocol.TCP
    assert summary.src_ip == "1.2.3.4"
    assert summary.dst_ip == "5.6.7.8"
    assert summary.src_port == 12345
    assert summary.dst_port == 80
    assert summary.timestamp.tzinfo == UTC


def test_summarise_udp_sets_correct_protocol() -> None:
    pkt = Ether() / IP(src="10.0.0.1", dst="10.0.0.2") / UDP(sport=5000, dport=53)
    pkt.time = 1_700_000_000.0
    summary = summarise_packet(pkt)
    assert summary.protocol == Protocol.UDP
    assert summary.src_port == 5000


def test_summarise_icmp_sets_correct_protocol() -> None:
    pkt = Ether() / IP() / ICMP()
    pkt.time = 1_700_000_000.0
    summary = summarise_packet(pkt)
    assert summary.protocol == Protocol.ICMP

# ---------------------------------------------------------------------------
# DNS
# ---------------------------------------------------------------------------


def test_summarise_dns_extracts_query_name() -> None:
    pkt = Ether() / IP() / UDP() / DNS(qd=DNSQR(qname="evil.example.com"))
    pkt.time = 1_700_000_000.0
    summary = summarise_packet(pkt)
    assert summary.protocol == Protocol.DNS
    assert summary.dns_query == "evil.example.com"

# ---------------------------------------------------------------------------
# ARP
# ---------------------------------------------------------------------------


def test_summarise_arp_sets_ips() -> None:
    pkt = Ether() / ARP(psrc="192.168.1.1", pdst="192.168.1.2")
    pkt.time = 1_700_000_000.0
    summary = summarise_packet(pkt)
    assert summary.protocol == Protocol.ARP
    assert summary.src_ip == "192.168.1.1"
    assert summary.dst_ip == "192.168.1.2"

# ---------------------------------------------------------------------------
# IPv6
# ---------------------------------------------------------------------------


def test_summarise_ipv6_packet() -> None:
    pkt = Ether() / IPv6(src="::1", dst="::2") / TCP()
    pkt.time = 1_700_000_000.0
    summary = summarise_packet(pkt)
    assert summary.src_ip == "::1"
    assert summary.dst_ip == "::2"

# ---------------------------------------------------------------------------
# Summary string
# ---------------------------------------------------------------------------


def test_summary_string_contains_ips_and_protocol() -> None:
    pkt = Ether() / IP(src="1.1.1.1", dst="2.2.2.2") / TCP(sport=100, dport=200)
    pkt.time = 1_700_000_000.0
    summary = summarise_packet(pkt)
    assert "1.1.1.1" in summary.summary
    assert "2.2.2.2" in summary.summary
    assert "tcp" in summary.summary.lower()
