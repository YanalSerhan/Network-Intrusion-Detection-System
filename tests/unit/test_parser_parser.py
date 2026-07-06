"""
Unit tests for parser/parser.py — PacketParser service.

Covers: parse(), parse_safe(), validate(), lifecycle (start/stop/health),
and integration with all extractor-backed protocol fields.
No real network traffic required — all packets crafted in-memory.
"""

from scapy.layers.dns import DNS, DNSQR
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.l2 import Ether
from scapy.packet import Raw

from network_defender.constants import Protocol
from network_defender.parser.parser import PacketParser

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_TS = 1_700_000_000.0


def _pkt(layers: object) -> object:
    p = layers  # type: ignore[assignment]
    p.time = _TS  # type: ignore[union-attr]
    return p


def _build_tls_client_hello(sni: str) -> bytes:
    """Minimal TLS 1.2 ClientHello with SNI."""
    sni_bytes = sni.encode()
    sni_name_len = len(sni_bytes).to_bytes(2, "big")
    sni_entry = b"\x00" + sni_name_len + sni_bytes
    sni_list_len = len(sni_entry).to_bytes(2, "big")
    sni_ext_data = sni_list_len + sni_entry
    sni_ext = b"\x00\x00" + len(sni_ext_data).to_bytes(2, "big") + sni_ext_data
    ext_total = len(sni_ext).to_bytes(2, "big")
    ciphers = b"\x00\x02\x00\x2f"
    body = b"\x03\x03" + b"\x00" * 32 + b"\x00" + ciphers + b"\x01\x00" + ext_total + sni_ext
    handshake = b"\x01" + len(body).to_bytes(3, "big") + body
    return b"\x16\x03\x03" + len(handshake).to_bytes(2, "big") + handshake


# ---------------------------------------------------------------------------
# Fixtures / setup
# ---------------------------------------------------------------------------


def _started_parser() -> PacketParser:
    """Return a started PacketParser instance."""
    p = PacketParser()
    p.start()
    return p


# ---------------------------------------------------------------------------
# Lifecycle tests
# ---------------------------------------------------------------------------


def test_parser_starts_and_is_running() -> None:
    parser = PacketParser()
    parser.start()
    assert parser.is_running is True
    parser.stop()
    assert parser.is_running is False


def test_health_check_after_start() -> None:
    parser = _started_parser()
    health = parser.health_check()
    assert health["running"] is True
    assert health["service"] == "PacketParser"
    assert health["packets_parsed"] == 0
    assert health["packets_failed"] == 0
    parser.stop()


def test_health_check_counts_parsed() -> None:
    parser = _started_parser()
    pkt = _pkt(Ether() / IP(src="1.2.3.4", dst="5.6.7.8") / TCP(sport=100, dport=80))
    parser.parse(pkt)  # type: ignore[arg-type]
    health = parser.health_check()
    assert health["packets_parsed"] == 1
    parser.stop()


# ---------------------------------------------------------------------------
# validate()
# ---------------------------------------------------------------------------


def test_validate_returns_false_for_none() -> None:
    parser = PacketParser()
    assert parser.validate(None) is False


def test_validate_returns_false_for_string() -> None:
    parser = PacketParser()
    assert parser.validate("not a packet") is False


def test_validate_returns_true_for_packet() -> None:
    parser = PacketParser()
    pkt = Ether() / IP() / TCP()
    pkt.time = _TS
    assert parser.validate(pkt) is True


# ---------------------------------------------------------------------------
# parse() — field population
# ---------------------------------------------------------------------------


def test_parse_tcp_ip_packet() -> None:
    parser = _started_parser()
    pkt = _pkt(Ether() / IP(src="1.2.3.4", dst="5.6.7.8") / TCP(sport=12345, dport=443))
    result = parser.parse(pkt)  # type: ignore[arg-type]
    assert result.src_ip == "1.2.3.4"
    assert result.dst_ip == "5.6.7.8"
    assert result.src_port == 12345
    assert result.dst_port == 443
    assert result.protocol == Protocol.TCP
    assert result.tcp_flags is not None
    parser.stop()


def test_parse_dns_packet() -> None:
    parser = _started_parser()
    pkt = _pkt(Ether() / IP() / UDP() / DNS(qd=DNSQR(qname="evil.example.com", qtype=1)))
    result = parser.parse(pkt)  # type: ignore[arg-type]
    assert result.protocol == Protocol.DNS
    assert result.dns is not None
    assert result.dns.query_name == "evil.example.com"
    parser.stop()


def test_parse_tls_extracts_sni() -> None:
    parser = _started_parser()
    raw_tls = _build_tls_client_hello("secure.example.com")
    pkt = _pkt(Ether() / IP() / TCP(dport=443) / Raw(raw_tls))
    result = parser.parse(pkt)  # type: ignore[arg-type]
    assert result.protocol == Protocol.TLS
    assert result.tls is not None
    assert result.tls.sni == "secure.example.com"
    parser.stop()


def test_parse_packet_has_raw_summary() -> None:
    parser = _started_parser()
    pkt = _pkt(Ether() / IP(src="1.1.1.1", dst="2.2.2.2") / TCP(sport=10, dport=20))
    result = parser.parse(pkt)  # type: ignore[arg-type]
    assert "1.1.1.1" in result.raw_summary
    assert "2.2.2.2" in result.raw_summary
    parser.stop()


def test_parse_raises_on_none() -> None:
    parser = _started_parser()
    import pytest

    with pytest.raises(ValueError, match="invalid packet"):
        parser.parse(None)  # type: ignore[arg-type]
    parser.stop()


# ---------------------------------------------------------------------------
# parse_safe()
# ---------------------------------------------------------------------------


def test_parse_safe_returns_none_for_none_input() -> None:
    parser = _started_parser()
    result = parser.parse_safe(None)  # type: ignore[arg-type]
    assert result is None
    parser.stop()


def test_parse_safe_returns_parsed_packet_on_valid_input() -> None:
    parser = _started_parser()
    pkt = _pkt(Ether() / IP() / TCP())
    result = parser.parse_safe(pkt)  # type: ignore[arg-type]
    assert result is not None
    assert result.length > 0
    parser.stop()


def test_parse_safe_increments_failed_on_none() -> None:
    parser = _started_parser()
    parser.parse_safe(None)  # type: ignore[arg-type]
    health = parser.health_check()
    assert health["packets_failed"] == 1
    parser.stop()
