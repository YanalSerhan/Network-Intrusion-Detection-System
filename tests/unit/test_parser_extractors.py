"""
Unit tests for parser/extractors.py.

All packets are crafted in-memory — no real network traffic required.
Covers: valid packets, missing layers, malformed/corrupt bytes, and edge cases.
"""


from scapy.layers.dns import DNS, DNSQR
from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.layers.inet6 import IPv6
from scapy.layers.l2 import ARP, Ether
from scapy.packet import Raw

from network_defender.parser.extractors import (
    extract_dns_fields,
    extract_http_fields,
    extract_ip_addresses,
    extract_ports,
    extract_tcp_flags,
    extract_tls_fields,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_TS = 1_700_000_000.0


def _pkt(layers: object) -> object:
    p = layers  # type: ignore[assignment]
    p.time = _TS  # type: ignore[union-attr]
    return p


def _build_tls_client_hello(sni: str) -> bytes:
    """Build a minimal TLS 1.2 ClientHello with the given SNI."""
    sni_bytes = sni.encode()
    sni_name_len = len(sni_bytes).to_bytes(2, "big")
    sni_entry = b"\x00" + sni_name_len + sni_bytes
    sni_list_len = len(sni_entry).to_bytes(2, "big")
    sni_ext_data = sni_list_len + sni_entry
    sni_ext = b"\x00\x00" + len(sni_ext_data).to_bytes(2, "big") + sni_ext_data
    ext_total = len(sni_ext).to_bytes(2, "big")
    cipher_suites = b"\x00\x2f"
    ciphers = b"\x00\x02" + cipher_suites
    client_hello_body = (
        b"\x03\x03" + b"\x00" * 32 + b"\x00" + ciphers + b"\x01\x00" + ext_total + sni_ext
    )
    handshake = b"\x01" + len(client_hello_body).to_bytes(3, "big") + client_hello_body
    return b"\x16\x03\x03" + len(handshake).to_bytes(2, "big") + handshake


# ---------------------------------------------------------------------------
# extract_ip_addresses
# ---------------------------------------------------------------------------


def test_extract_ip_ipv4() -> None:
    pkt = _pkt(Ether() / IP(src="1.2.3.4", dst="5.6.7.8") / TCP())
    src, dst = extract_ip_addresses(pkt)  # type: ignore[arg-type]
    assert src == "1.2.3.4"
    assert dst == "5.6.7.8"


def test_extract_ip_ipv6() -> None:
    pkt = _pkt(Ether() / IPv6(src="::1", dst="::2") / TCP())
    src, dst = extract_ip_addresses(pkt)  # type: ignore[arg-type]
    assert src == "::1"
    assert dst == "::2"


def test_extract_ip_arp() -> None:
    pkt = _pkt(Ether() / ARP(psrc="10.0.0.1", pdst="10.0.0.2"))
    src, dst = extract_ip_addresses(pkt)  # type: ignore[arg-type]
    assert src == "10.0.0.1"
    assert dst == "10.0.0.2"


def test_extract_ip_no_ip_layer() -> None:
    pkt = _pkt(Ether())
    src, dst = extract_ip_addresses(pkt)  # type: ignore[arg-type]
    assert src is None
    assert dst is None


# ---------------------------------------------------------------------------
# extract_ports
# ---------------------------------------------------------------------------


def test_extract_ports_tcp() -> None:
    pkt = _pkt(Ether() / IP() / TCP(sport=12345, dport=443))
    src, dst = extract_ports(pkt)  # type: ignore[arg-type]
    assert src == 12345
    assert dst == 443


def test_extract_ports_udp() -> None:
    pkt = _pkt(Ether() / IP() / UDP(sport=5000, dport=53))
    src, dst = extract_ports(pkt)  # type: ignore[arg-type]
    assert src == 5000
    assert dst == 53


def test_extract_ports_icmp_returns_none() -> None:
    pkt = _pkt(Ether() / IP() / ICMP())
    src, dst = extract_ports(pkt)  # type: ignore[arg-type]
    assert src is None
    assert dst is None


# ---------------------------------------------------------------------------
# extract_tcp_flags
# ---------------------------------------------------------------------------


def test_extract_tcp_flags_syn() -> None:
    pkt = _pkt(Ether() / IP() / TCP(flags="S"))
    flags = extract_tcp_flags(pkt)  # type: ignore[arg-type]
    assert flags is not None
    assert flags.syn is True
    assert flags.ack is False


def test_extract_tcp_flags_syn_ack() -> None:
    pkt = _pkt(Ether() / IP() / TCP(flags="SA"))
    flags = extract_tcp_flags(pkt)  # type: ignore[arg-type]
    assert flags is not None
    assert flags.syn is True
    assert flags.ack is True


def test_extract_tcp_flags_fin() -> None:
    pkt = _pkt(Ether() / IP() / TCP(flags="F"))
    flags = extract_tcp_flags(pkt)  # type: ignore[arg-type]
    assert flags is not None
    assert flags.fin is True


def test_extract_tcp_flags_rst() -> None:
    pkt = _pkt(Ether() / IP() / TCP(flags="R"))
    flags = extract_tcp_flags(pkt)  # type: ignore[arg-type]
    assert flags is not None
    assert flags.rst is True


def test_extract_tcp_flags_no_tcp_returns_none() -> None:
    pkt = _pkt(Ether() / IP() / UDP())
    flags = extract_tcp_flags(pkt)  # type: ignore[arg-type]
    assert flags is None


# ---------------------------------------------------------------------------
# extract_dns_fields
# ---------------------------------------------------------------------------


def test_extract_dns_query() -> None:
    pkt = _pkt(Ether() / IP() / UDP() / DNS(qd=DNSQR(qname="example.com", qtype=1)))
    dns = extract_dns_fields(pkt)  # type: ignore[arg-type]
    assert dns is not None
    assert dns.query_name == "example.com"
    assert dns.record_type == 1


def test_extract_dns_no_dns_returns_none() -> None:
    pkt = _pkt(Ether() / IP() / TCP())
    dns = extract_dns_fields(pkt)  # type: ignore[arg-type]
    assert dns is None


# ---------------------------------------------------------------------------
# extract_http_fields
# ---------------------------------------------------------------------------


def test_extract_http_no_http_layer_returns_none() -> None:
    pkt = _pkt(Ether() / IP() / TCP(dport=80))
    http = extract_http_fields(pkt)  # type: ignore[arg-type]
    assert http is None


# ---------------------------------------------------------------------------
# extract_tls_fields
# ---------------------------------------------------------------------------


def test_extract_tls_extracts_sni() -> None:
    raw_tls = _build_tls_client_hello("secure.example.com")
    pkt = _pkt(Ether() / IP() / TCP(dport=443) / Raw(raw_tls))
    tls = extract_tls_fields(pkt)  # type: ignore[arg-type]
    assert tls is not None
    assert tls.sni == "secure.example.com"
    assert tls.cipher_suites is not None
    assert len(tls.cipher_suites) > 0


def test_extract_tls_no_tcp_returns_none() -> None:
    pkt = _pkt(Ether() / IP() / UDP())
    tls = extract_tls_fields(pkt)  # type: ignore[arg-type]
    assert tls is None


def test_extract_tls_non_tls_tcp_returns_none() -> None:
    """A plain TCP packet (no TLS record marker) returns None."""
    pkt = _pkt(Ether() / IP() / TCP(dport=443) / Raw(b"GET / HTTP/1.1\r\n"))
    tls = extract_tls_fields(pkt)  # type: ignore[arg-type]
    assert tls is None


def test_extract_tls_malformed_bytes_returns_none() -> None:
    """Corrupt TLS bytes (starts with 0x16 but truncated) return None gracefully."""
    pkt = _pkt(Ether() / IP() / TCP(dport=443) / Raw(b"\x16\x03\x03\x00"))
    tls = extract_tls_fields(pkt)  # type: ignore[arg-type]
    assert tls is None


def test_extract_tls_server_hello_not_extracted() -> None:
    """ServerHello (type 0x02) is not extracted; only ClientHello is supported."""
    raw = b"\x16\x03\x03\x00\x05\x02\x00\x00\x00\x00"  # type 0x02 = ServerHello
    pkt = _pkt(Ether() / IP() / TCP(dport=443) / Raw(raw))
    tls = extract_tls_fields(pkt)  # type: ignore[arg-type]
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
    assert extract_ip_addresses(broken) == (None, None)  # type: ignore[arg-type]
    assert extract_ports(broken) == (None, None)  # type: ignore[arg-type]
    assert extract_tcp_flags(broken) is None  # type: ignore[arg-type]
    assert extract_dns_fields(broken) is None  # type: ignore[arg-type]
    assert extract_http_fields(broken) is None  # type: ignore[arg-type]
    assert extract_tls_fields(broken) is None  # type: ignore[arg-type]

