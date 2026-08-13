"""
Scapy packet crafting helpers shared by the capture and parser suites.

Data Setup:  Nothing — every helper is a pure function.
Data Input:  Scapy layers, or the field a test wants to vary.
Data Output: A Scapy packet with a usable ``.time``, or raw protocol bytes.

Three suites previously carried their own byte-for-byte copy of the TLS
ClientHello builder. One copy means a fix to the record framing is a fix
everywhere, and a test that fails here fails for a reason in the code under
test rather than in its private copy of the fixture data.
"""

from typing import Any

from scapy.layers.inet import IP, TCP
from scapy.layers.l2 import Ether

#: Fixed capture time. Constant rather than "now" so summaries and parsed
#: packets are byte-identical between runs, which is what makes golden-file
#: comparison possible.
CAPTURE_TIMESTAMP = 1_700_000_000.0


def stamped(packet: Any, timestamp: float = CAPTURE_TIMESTAMP) -> Any:
    """
    Give a crafted packet the arrival time Scapy would have set on capture.

    Args:
        packet:    A Scapy packet built from layers.
        timestamp: Epoch seconds to stamp onto it.

    Returns:
        The same packet, with ``.time`` set.
    """
    packet.time = timestamp
    return packet


def tcp_packet(
    src: str = "1.2.3.4",
    dst: str = "5.6.7.8",
    sport: int = 12345,
    dport: int = 80,
    **flags: Any,
) -> Any:
    """
    Build a stamped Ethernet/IP/TCP packet.

    Args:
        src:     Source IP address.
        dst:     Destination IP address.
        sport:   Source port.
        dport:   Destination port.
        **flags: Extra TCP fields, e.g. ``flags="S"``.

    Returns:
        A Scapy packet ready to hand to the capture or parser code.
    """
    return stamped(Ether() / IP(src=src, dst=dst) / TCP(sport=sport, dport=dport, **flags))


def tls_client_hello(sni: str) -> bytes:
    """
    Build a minimal TLS 1.2 ClientHello record carrying one SNI extension.

    The record is assembled by hand rather than with Scapy's TLS layer, which
    is an optional import: the parser only reads the handshake header and the
    server_name extension, so the smallest well-formed record that carries
    them is enough to exercise it — and is stable across Scapy versions.

    Args:
        sni: The server name to advertise.

    Returns:
        The complete TLS record as bytes, ready to use as a TCP payload.
    """
    sni_bytes = sni.encode()
    # server_name entry: type host_name(0), then a 2-byte length and the name.
    sni_entry = b"\x00" + len(sni_bytes).to_bytes(2, "big") + sni_bytes
    sni_ext_data = len(sni_entry).to_bytes(2, "big") + sni_entry
    sni_ext = b"\x00\x00" + len(sni_ext_data).to_bytes(2, "big") + sni_ext_data

    ciphers = b"\x00\x02" + b"\x00\x2f"  # one suite: TLS_RSA_WITH_AES_128_CBC_SHA
    body = (
        b"\x03\x03"  # client version: TLS 1.2
        + b"\x00" * 32  # random
        + b"\x00"  # empty session id
        + ciphers
        + b"\x01\x00"  # compression methods: null
        + len(sni_ext).to_bytes(2, "big")
        + sni_ext
    )
    handshake = b"\x01" + len(body).to_bytes(3, "big") + body
    return b"\x16\x03\x03" + len(handshake).to_bytes(2, "big") + handshake
