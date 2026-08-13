"""
Layer 7 field extraction: DNS, HTTP and TLS.

Data Setup:  No state; pure functions over Scapy packets.
Data Input:  A Scapy Packet.
Data Output: Protocol-specific field models, or None when the layer is absent.

TLS is metadata only — SNI and offered cipher suites from the ClientHello. No
decryption, per the PRD's explicit non-goal.
"""

from scapy.layers.dns import DNSQR
from scapy.layers.http import HTTPRequest
from scapy.layers.inet import TCP
from scapy.packet import Packet

from ..constants import TlsHandshakeType
from .models import DnsFields, HttpFields, TlsFields

# TLS record content-type for handshake messages (RFC 5246 §6.2.1)
_TLS_CONTENT_TYPE_HANDSHAKE = 0x16
_TLS_SNI_EXTENSION_TYPE = 0x0000




def extract_dns_fields(packet: Packet) -> DnsFields | None:
    """
    Extract DNS query name and record type from the first DNSQR record.

    Args:
        packet: Scapy packet object.

    Returns:
        DnsFields model, or None if no DNS query record is present.
    """
    try:
        if not packet.haslayer(DNSQR):
            return None
        question = packet[DNSQR]
        query_name = (question.qname or b"").decode("utf-8", "replace").rstrip(".")
        return DnsFields(query_name=query_name or None, record_type=int(question.qtype))
    except Exception:
        return None


def extract_http_fields(packet: Packet) -> HttpFields | None:
    """
    Extract HTTP/1.x request fields from the HTTPRequest Scapy layer.

    Args:
        packet: Scapy packet object.

    Returns:
        HttpFields model, or None if no HTTPRequest layer is present.
    """
    try:
        if not packet.haslayer(HTTPRequest):
            return None
        req = packet[HTTPRequest]
        return HttpFields(
            method=(req.Method or b"").decode("utf-8", "replace") or None,
            path=(req.Path or b"").decode("utf-8", "replace") or None,
            host=(req.Host or b"").decode("utf-8", "replace") or None,
            user_agent=(req.User_Agent or b"").decode("utf-8", "replace") or None,
        )
    except Exception:
        return None


def extract_tls_fields(packet: Packet) -> TlsFields | None:
    """
    Extract TLS ClientHello metadata (SNI + cipher suites) from a TCP payload.

    Performs metadata-only extraction — no key material, no decryption.

    Args:
        packet: Scapy packet object.

    Returns:
        TlsFields model, or None if no TLS ClientHello is detected.
    """
    try:
        if not packet.haslayer(TCP):
            return None
        raw = bytes(packet[TCP].payload)
        if len(raw) < 6 or raw[0] != _TLS_CONTENT_TYPE_HANDSHAKE:
            return None
        if raw[5] != TlsHandshakeType.CLIENT_HELLO:
            return None
        offset = 9  # record header(5) + handshake type(1) + length(3)
        offset += 2  # client version
        offset += 32  # random
        if offset >= len(raw):
            return None
        session_id_len = raw[offset]
        offset += 1 + session_id_len
        if offset + 2 > len(raw):
            return None
        cipher_len = int.from_bytes(raw[offset: offset + 2], "big")
        offset += 2
        cipher_suites = [
            int.from_bytes(raw[offset + i: offset + i + 2], "big")
            for i in range(0, cipher_len, 2)
        ]
        offset += cipher_len
        if offset >= len(raw):
            return TlsFields(sni=None, cipher_suites=cipher_suites)
        offset += 1 + raw[offset]  # compression methods
        if offset + 2 > len(raw):
            return TlsFields(sni=None, cipher_suites=cipher_suites)
        ext_total = int.from_bytes(raw[offset: offset + 2], "big")
        offset += 2
        end = offset + ext_total
        sni: str | None = None
        while offset + 4 <= end:
            ext_type = int.from_bytes(raw[offset: offset + 2], "big")
            ext_len = int.from_bytes(raw[offset + 2: offset + 4], "big")
            offset += 4
            if ext_type == _TLS_SNI_EXTENSION_TYPE and offset + ext_len <= end:
                name_offset = offset + 3
                name_len = int.from_bytes(raw[offset + 3: offset + 5], "big")
                sni = raw[name_offset + 2: name_offset + 2 + name_len].decode("utf-8", "replace")
                break
            offset += ext_len
        return TlsFields(sni=sni, cipher_suites=cipher_suites)
    except Exception:
        return None
