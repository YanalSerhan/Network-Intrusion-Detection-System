"""Tests for extracting ports and TCP flags from the transport layer."""

from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.layers.l2 import Ether

from network_defender.parser.extractors import (
    extract_ports,
    extract_tcp_flags,
)
from tests.fixtures.packets import stamped

# ---------------------------------------------------------------------------
# extract_ports
# ---------------------------------------------------------------------------


def test_extract_ports_tcp() -> None:
    packet = stamped(Ether() / IP() / TCP(sport=12345, dport=443))
    src, dst = extract_ports(packet)
    assert src == 12345
    assert dst == 443


def test_extract_ports_udp() -> None:
    packet = stamped(Ether() / IP() / UDP(sport=5000, dport=53))
    src, dst = extract_ports(packet)
    assert src == 5000
    assert dst == 53


def test_extract_ports_icmp_returns_none() -> None:
    packet = stamped(Ether() / IP() / ICMP())
    src, dst = extract_ports(packet)
    assert src is None
    assert dst is None

# ---------------------------------------------------------------------------
# extract_tcp_flags
# ---------------------------------------------------------------------------


def test_extract_tcp_flags_syn() -> None:
    packet = stamped(Ether() / IP() / TCP(flags="S"))
    flags = extract_tcp_flags(packet)
    assert flags is not None
    assert flags.syn is True
    assert flags.ack is False


def test_extract_tcp_flags_syn_ack() -> None:
    packet = stamped(Ether() / IP() / TCP(flags="SA"))
    flags = extract_tcp_flags(packet)
    assert flags is not None
    assert flags.syn is True
    assert flags.ack is True


def test_extract_tcp_flags_fin() -> None:
    packet = stamped(Ether() / IP() / TCP(flags="F"))
    flags = extract_tcp_flags(packet)
    assert flags is not None
    assert flags.fin is True


def test_extract_tcp_flags_rst() -> None:
    packet = stamped(Ether() / IP() / TCP(flags="R"))
    flags = extract_tcp_flags(packet)
    assert flags is not None
    assert flags.rst is True


def test_extract_tcp_flags_no_tcp_returns_none() -> None:
    packet = stamped(Ether() / IP() / UDP())
    flags = extract_tcp_flags(packet)
    assert flags is None
