"""
Unit tests for parser/models.py.

Verifies Pydantic model field names, types, defaults, and round-trip serialisation.
No real network traffic required — all data constructed in-memory.
"""

from datetime import UTC, datetime

from network_defender.constants import Protocol
from network_defender.parser.models import (
    DnsFields,
    HttpFields,
    ParsedPacket,
    TcpFlags,
    TlsFields,
)

# ---------------------------------------------------------------------------
# TcpFlags
# ---------------------------------------------------------------------------


def test_tcp_flags_defaults_are_false() -> None:
    """All TCP flag fields default to False."""
    flags = TcpFlags()
    assert flags.syn is False
    assert flags.ack is False
    assert flags.fin is False
    assert flags.rst is False
    assert flags.psh is False
    assert flags.urg is False


def test_tcp_flags_syn_ack() -> None:
    """SYN-ACK can be constructed correctly."""
    flags = TcpFlags(syn=True, ack=True)
    assert flags.syn is True
    assert flags.ack is True
    assert flags.fin is False


# ---------------------------------------------------------------------------
# DnsFields
# ---------------------------------------------------------------------------


def test_dns_fields_stores_query_name() -> None:
    dns = DnsFields(query_name="evil.example.com", record_type=1)
    assert dns.query_name == "evil.example.com"
    assert dns.record_type == 1


def test_dns_fields_defaults_none() -> None:
    dns = DnsFields()
    assert dns.query_name is None
    assert dns.record_type is None


# ---------------------------------------------------------------------------
# HttpFields
# ---------------------------------------------------------------------------


def test_http_fields_stores_all_request_fields() -> None:
    http = HttpFields(method="GET", path="/login", host="example.com", user_agent="curl/7.x")
    assert http.method == "GET"
    assert http.path == "/login"
    assert http.host == "example.com"
    assert http.user_agent == "curl/7.x"


def test_http_fields_defaults_none() -> None:
    http = HttpFields()
    assert http.method is None
    assert http.host is None


# ---------------------------------------------------------------------------
# TlsFields
# ---------------------------------------------------------------------------


def test_tls_fields_stores_sni_and_ciphers() -> None:
    tls = TlsFields(sni="secure.example.com", cipher_suites=[0x002F, 0x0035])
    assert tls.sni == "secure.example.com"
    assert tls.cipher_suites == [0x002F, 0x0035]


def test_tls_fields_defaults_none() -> None:
    tls = TlsFields()
    assert tls.sni is None
    assert tls.cipher_suites is None


# ---------------------------------------------------------------------------
# ParsedPacket
# ---------------------------------------------------------------------------


def _make_parsed_packet(**kwargs: object) -> ParsedPacket:
    """Build a minimal valid ParsedPacket for testing."""
    defaults: dict = {
        "timestamp": datetime(2024, 1, 1, tzinfo=UTC),
        "protocol": Protocol.TCP,
        "length": 60,
        "raw_summary": "tcp 1.2.3.4:80 → 5.6.7.8:443 len=60",
    }
    defaults.update(kwargs)
    return ParsedPacket(**defaults)  # type: ignore[arg-type]


def test_parsed_packet_required_fields() -> None:
    pkt = _make_parsed_packet()
    assert pkt.protocol == Protocol.TCP
    assert pkt.length == 60
    assert pkt.timestamp.tzinfo == UTC


def test_parsed_packet_optional_fields_default_none() -> None:
    pkt = _make_parsed_packet()
    assert pkt.src_ip is None
    assert pkt.dst_ip is None
    assert pkt.src_port is None
    assert pkt.dst_port is None
    assert pkt.tcp_flags is None
    assert pkt.dns is None
    assert pkt.http is None
    assert pkt.tls is None


def test_parsed_packet_round_trips_model_dump() -> None:
    """model_dump() should produce a dict that can reconstruct the model."""
    original = _make_parsed_packet(
        src_ip="1.2.3.4",
        dst_ip="5.6.7.8",
        src_port=12345,
        dst_port=443,
        tcp_flags=TcpFlags(syn=True),
        tls=TlsFields(sni="test.example.com"),
    )
    dumped = original.model_dump()
    restored = ParsedPacket(**dumped)
    assert restored == original
