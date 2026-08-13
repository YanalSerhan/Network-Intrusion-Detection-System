"""
Tests for reading TLS ClientHello metadata out of raw bytes.

The record is walked by hand, offset by offset, because Scapy's TLS layer is
optional and raises on exactly the truncated handshakes a sensor sees all
day. Hand-walked offsets are also the easiest thing in the codebase to get
wrong, and every wrong one reads past the end of a buffer — so the cases here
are mostly deliberately broken records.

Nothing may raise: missing metadata degrades an alert, an exception drops the
packet that would have raised it.
"""

from typing import Any

from scapy.layers.inet import IP, TCP
from scapy.layers.l2 import Ether
from scapy.packet import Raw

from network_defender.capture.tls_metadata import extract_tls_metadata
from tests.fixtures.packets import tls_client_hello

#: The single suite offered by the fixture builder.
TLS_RSA_WITH_AES_128_CBC_SHA = 0x002F


def _with_payload(payload: bytes) -> Any:
    """Wrap raw bytes as the TCP payload of a packet."""
    return Ether() / IP() / TCP(dport=443) / Raw(load=payload)


def test_sni_and_ciphers_are_read_from_a_well_formed_hello() -> None:
    sni, ciphers = extract_tls_metadata(_with_payload(tls_client_hello("secure.example")))

    assert sni == "secure.example"
    assert ciphers == [TLS_RSA_WITH_AES_128_CBC_SHA]


def test_a_non_tls_payload_yields_nothing() -> None:
    """Plain HTTP on 443 happens; it is not a parse failure."""
    assert extract_tls_metadata(_with_payload(b"GET / HTTP/1.1\r\n\r\n")) == (None, None)


def test_a_payload_too_short_to_be_a_record_yields_nothing() -> None:
    assert extract_tls_metadata(_with_payload(b"\x16\x03\x03")) == (None, None)


def test_a_handshake_that_is_not_a_client_hello_is_ignored() -> None:
    """ServerHello carries no SNI; reading one as a ClientHello is nonsense."""
    record = bytearray(tls_client_hello("secure.example"))
    record[5] = 0x02  # server_hello

    assert extract_tls_metadata(_with_payload(bytes(record))) == (None, None)


def test_a_record_truncated_mid_handshake_does_not_raise() -> None:
    """A packet cut short by the snaplen must degrade, not explode."""
    truncated = tls_client_hello("secure.example")[:20]

    assert extract_tls_metadata(_with_payload(truncated)) == (None, None)


def test_ciphers_survive_a_hello_with_no_extension_block() -> None:
    """The cipher list is complete before the extensions start."""
    full = tls_client_hello("secure.example")
    # Cut at the point where the extension total length would begin: session
    # id (1) + ciphers (2 + 2) + compression (2) after the fixed prefix.
    without_extensions = full[: 9 + 2 + 32 + 1 + 4 + 2]

    sni, ciphers = extract_tls_metadata(_with_payload(without_extensions))
    assert sni is None
    assert ciphers == [TLS_RSA_WITH_AES_128_CBC_SHA]


def test_a_hello_without_sni_still_reports_its_ciphers() -> None:
    """Not every client sends SNI; the flow is still worth characterising."""
    record = bytearray(tls_client_hello("secure.example"))
    sni_type_offset = record.index(b"\x00\x00", 9 + 2 + 32 + 1 + 4 + 2 + 2)
    record[sni_type_offset : sni_type_offset + 2] = b"\x00\x17"  # extended_master_secret

    sni, ciphers = extract_tls_metadata(_with_payload(bytes(record)))
    assert sni is None
    assert ciphers == [TLS_RSA_WITH_AES_128_CBC_SHA]


def test_a_packet_without_tcp_yields_nothing() -> None:
    """The extractor is called on everything; most packets are not TLS."""
    assert extract_tls_metadata(Ether() / IP()) == (None, None)
