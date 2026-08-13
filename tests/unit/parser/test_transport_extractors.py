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
    pkt = stamped(Ether() / IP() / TCP(sport=12345, dport=443))
    src, dst = extract_ports(pkt)  # type: ignore[arg-type]
    assert src == 12345
    assert dst == 443


def test_extract_ports_udp() -> None:
    pkt = stamped(Ether() / IP() / UDP(sport=5000, dport=53))
    src, dst = extract_ports(pkt)  # type: ignore[arg-type]
    assert src == 5000
    assert dst == 53


def test_extract_ports_icmp_returns_none() -> None:
    pkt = stamped(Ether() / IP() / ICMP())
    src, dst = extract_ports(pkt)  # type: ignore[arg-type]
    assert src is None
    assert dst is None

# ---------------------------------------------------------------------------
# extract_tcp_flags
# ---------------------------------------------------------------------------


def test_extract_tcp_flags_syn() -> None:
    pkt = stamped(Ether() / IP() / TCP(flags="S"))
    flags = extract_tcp_flags(pkt)  # type: ignore[arg-type]
    assert flags is not None
    assert flags.syn is True
    assert flags.ack is False


def test_extract_tcp_flags_syn_ack() -> None:
    pkt = stamped(Ether() / IP() / TCP(flags="SA"))
    flags = extract_tcp_flags(pkt)  # type: ignore[arg-type]
    assert flags is not None
    assert flags.syn is True
    assert flags.ack is True


def test_extract_tcp_flags_fin() -> None:
    pkt = stamped(Ether() / IP() / TCP(flags="F"))
    flags = extract_tcp_flags(pkt)  # type: ignore[arg-type]
    assert flags is not None
    assert flags.fin is True


def test_extract_tcp_flags_rst() -> None:
    pkt = stamped(Ether() / IP() / TCP(flags="R"))
    flags = extract_tcp_flags(pkt)  # type: ignore[arg-type]
    assert flags is not None
    assert flags.rst is True


def test_extract_tcp_flags_no_tcp_returns_none() -> None:
    pkt = stamped(Ether() / IP() / UDP())
    flags = extract_tcp_flags(pkt)  # type: ignore[arg-type]
    assert flags is None
