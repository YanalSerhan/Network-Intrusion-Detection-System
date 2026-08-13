"""Tests that TLS metadata is read from a ClientHello without decrypting anything."""


from scapy.layers.inet import IP, TCP
from scapy.layers.l2 import Ether

from network_defender.capture.packet_summary import summarise_packet
from network_defender.constants import Protocol
from tests.fixtures.packets import tls_client_hello

# ---------------------------------------------------------------------------
# TLS (synthetic ClientHello byte blob)
# ---------------------------------------------------------------------------


def test_summarise_tls_extracts_sni() -> None:
    from scapy.packet import Raw

    raw_tls = tls_client_hello("secure.example.com")
    pkt = Ether() / IP() / TCP(dport=443) / Raw(raw_tls)
    pkt.time = 1_700_000_000.0
    summary = summarise_packet(pkt)
    assert summary.protocol == Protocol.TLS
    assert summary.tls_sni == "secure.example.com"
