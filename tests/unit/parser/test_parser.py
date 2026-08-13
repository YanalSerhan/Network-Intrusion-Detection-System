"""Tests for parse() field population and the non-raising parse_safe()."""

from scapy.layers.dns import DNS, DNSQR
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.l2 import Ether
from scapy.packet import Raw

from network_defender.constants import Protocol
from network_defender.parser.parser import PacketParser
from tests.fixtures.packets import stamped, tls_client_hello

# ---------------------------------------------------------------------------
# parse() — field population
# ---------------------------------------------------------------------------


def test_parse_tcp_ip_packet(started_parser: PacketParser) -> None:
    packet = stamped(Ether() / IP(src="1.2.3.4", dst="5.6.7.8") / TCP(sport=12345, dport=443))
    result = started_parser.parse(packet)
    assert result.src_ip == "1.2.3.4"
    assert result.dst_ip == "5.6.7.8"
    assert result.src_port == 12345
    assert result.dst_port == 443
    assert result.protocol == Protocol.TCP
    assert result.tcp_flags is not None
    started_parser.stop()


def test_parse_dns_packet(started_parser: PacketParser) -> None:
    packet = stamped(Ether() / IP() / UDP() / DNS(qd=DNSQR(qname="evil.example.com", qtype=1)))
    result = started_parser.parse(packet)
    assert result.protocol == Protocol.DNS
    assert result.dns is not None
    assert result.dns.query_name == "evil.example.com"
    started_parser.stop()


def test_parse_tls_extracts_sni(started_parser: PacketParser) -> None:
    raw_tls = tls_client_hello("secure.example.com")
    packet = stamped(Ether() / IP() / TCP(dport=443) / Raw(raw_tls))
    result = started_parser.parse(packet)
    assert result.protocol == Protocol.TLS
    assert result.tls is not None
    assert result.tls.sni == "secure.example.com"
    started_parser.stop()


def test_parse_packet_has_raw_summary(started_parser: PacketParser) -> None:
    packet = stamped(Ether() / IP(src="1.1.1.1", dst="2.2.2.2") / TCP(sport=10, dport=20))
    result = started_parser.parse(packet)
    assert "1.1.1.1" in result.raw_summary
    assert "2.2.2.2" in result.raw_summary
    started_parser.stop()


def test_parse_raises_on_none(started_parser: PacketParser) -> None:
    import pytest

    with pytest.raises(ValueError, match="invalid packet"):
        started_parser.parse(None)
    started_parser.stop()

# ---------------------------------------------------------------------------
# parse_safe()
# ---------------------------------------------------------------------------


def test_parse_safe_returns_none_for_none_input(started_parser: PacketParser) -> None:
    result = started_parser.parse_safe(None)
    assert result is None
    started_parser.stop()


def test_parse_safe_returns_parsed_packet_on_valid_input(started_parser: PacketParser) -> None:
    packet = stamped(Ether() / IP() / TCP())
    result = started_parser.parse_safe(packet)
    assert result is not None
    assert result.length > 0
    started_parser.stop()


def test_parse_safe_increments_failed_on_none(started_parser: PacketParser) -> None:
    started_parser.parse_safe(None)
    health = started_parser.health_check()
    assert health["packets_failed"] == 1
    started_parser.stop()
