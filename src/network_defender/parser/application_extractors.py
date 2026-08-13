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
from scapy.packet import Packet

from ..capture.tls_metadata import extract_tls_metadata
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
    Extract TLS ClientHello metadata (SNI and offered cipher suites).

    Metadata only — no key material is touched and nothing is decrypted, per
    the PRD's explicit non-goal.

    The record walking lives in `capture.tls_metadata`, which the capture layer
    already needs for its one-line packet summaries. Parsing the same bytes a
    second time here would mean two hand-written offset walks over the same
    structure, and hand-written offset walks are the easiest thing in this
    codebase to get subtly wrong.

    Args:
        packet: Scapy packet object.

    Returns:
        TlsFields model, or None if no TLS ClientHello is present.
    """
    sni, cipher_suites = extract_tls_metadata(packet)
    if sni is None and cipher_suites is None:
        return None
    return TlsFields(sni=sni, cipher_suites=cipher_suites)
