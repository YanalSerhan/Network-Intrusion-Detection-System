"""Tests for extracting DNS, HTTP and TLS fields, and for extractor resilience."""

from scapy.layers.dns import DNS, DNSQR
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.l2 import Ether
from scapy.packet import Raw

from network_defender.parser.extractors import (
    extract_dns_fields,
    extract_http_fields,
    extract_ip_addresses,
    extract_ports,
    extract_tcp_flags,
    extract_tls_fields,
)
from tests.fixtures.packets import stamped, tls_client_hello

# ---------------------------------------------------------------------------
# extract_dns_fields
# ---------------------------------------------------------------------------


def test_extract_dns_query() -> None:
    pkt = stamped(Ether() / IP() / UDP() / DNS(qd=DNSQR(qname="example.com", qtype=1)))
    dns = extract_dns_fields(pkt)
    assert dns is not None
    assert dns.query_name == "example.com"
    assert dns.record_type == 1


def test_extract_dns_no_dns_returns_none() -> None:
    pkt = stamped(Ether() / IP() / TCP())
    dns = extract_dns_fields(pkt)
    assert dns is None

# ---------------------------------------------------------------------------
# extract_http_fields
# ---------------------------------------------------------------------------


def test_extract_http_no_http_layer_returns_none() -> None:
    pkt = stamped(Ether() / IP() / TCP(dport=80))
    http = extract_http_fields(pkt)
    assert http is None

# ---------------------------------------------------------------------------
# extract_tls_fields
# ---------------------------------------------------------------------------


def test_extract_tls_extracts_sni() -> None:
    raw_tls = tls_client_hello("secure.example.com")
    pkt = stamped(Ether() / IP() / TCP(dport=443) / Raw(raw_tls))
    tls = extract_tls_fields(pkt)
    assert tls is not None
    assert tls.sni == "secure.example.com"
    assert tls.cipher_suites is not None
    assert len(tls.cipher_suites) > 0


def test_extract_tls_no_tcp_returns_none() -> None:
    pkt = stamped(Ether() / IP() / UDP())
    tls = extract_tls_fields(pkt)
    assert tls is None


def test_extract_tls_non_tls_tcp_returns_none() -> None:
    """A plain TCP packet (no TLS record marker) returns None."""
    pkt = stamped(Ether() / IP() / TCP(dport=443) / Raw(b"GET / HTTP/1.1\r\n"))
    tls = extract_tls_fields(pkt)
    assert tls is None


def test_extract_tls_malformed_bytes_returns_none() -> None:
    """Corrupt TLS bytes (starts with 0x16 but truncated) return None gracefully."""
    pkt = stamped(Ether() / IP() / TCP(dport=443) / Raw(b"\x16\x03\x03\x00"))
    tls = extract_tls_fields(pkt)
    assert tls is None


def test_extract_tls_server_hello_not_extracted() -> None:
    """ServerHello (type 0x02) is not extracted; only ClientHello is supported."""
    raw = b"\x16\x03\x03\x00\x05\x02\x00\x00\x00\x00"  # type 0x02 = ServerHello
    pkt = stamped(Ether() / IP() / TCP(dport=443) / Raw(raw))
    tls = extract_tls_fields(pkt)
    assert tls is None

# ---------------------------------------------------------------------------
# Exception handling
# ---------------------------------------------------------------------------


class BrokenPacket:
    """Mock packet that raises an exception when queried."""

    def haslayer(self, layer: object) -> bool:
        raise RuntimeError("simulated crash")


def test_all_extractors_handle_exceptions_gracefully() -> None:
    broken = BrokenPacket()
    assert extract_ip_addresses(broken) == (None, None)
    assert extract_ports(broken) == (None, None)
    assert extract_tcp_flags(broken) is None
    assert extract_dns_fields(broken) is None
    assert extract_http_fields(broken) is None
    assert extract_tls_fields(broken) is None
