"""
Protocol-field extractor functions for the packet parser layer.

Data Setup:  No configuration required; stateless pure functions.
Data Input:  A Scapy Packet object.
Data Output: Typed field values (or None) for each protocol layer.

Design principles:
  - Every extractor wraps its body in try/except so malformed or truncated
    packets never propagate exceptions to the caller.
  - Extractors are pure functions: no side effects, no global state.
  - Each function has a single responsibility (one protocol or one field group).

Note on TLS extraction:
  The TLS ClientHello parser below is a self-contained reimplementation rather
  than an import of the private ``_extract_tls_metadata`` in
  ``capture/packet_summary.py``. This keeps the capture and parser layers
  decoupled; the duplication is intentional and documented here.
"""

from scapy.layers.dns import DNSQR  # type: ignore[import-untyped]
from scapy.layers.http import HTTPRequest  # type: ignore[import-untyped]
from scapy.layers.inet import IP, TCP, UDP  # type: ignore[import-untyped]
from scapy.layers.inet6 import IPv6  # type: ignore[import-untyped]
from scapy.layers.l2 import ARP  # type: ignore[import-untyped]
from scapy.packet import Packet  # type: ignore[import-untyped]

from ..constants import TlsHandshakeType
from .models import DnsFields, HttpFields, TcpFlags, TlsFields

# TLS record content-type for handshake messages (RFC 5246 §6.2.1)
_TLS_CONTENT_TYPE_HANDSHAKE = 0x16
_TLS_SNI_EXTENSION_TYPE = 0x0000


def extract_ip_addresses(pkt: Packet) -> tuple[str | None, str | None]:
    """
    Extract source and destination IP addresses from a packet.

    Supports IPv4, IPv6, and ARP layers (in priority order).

    Args:
        pkt: Scapy packet object.

    Returns:
        Tuple of (src_ip, dst_ip); both None if no IP layer is present.
    """
    try:
        if pkt.haslayer(IP):
            return pkt[IP].src, pkt[IP].dst
        if pkt.haslayer(IPv6):
            return pkt[IPv6].src, pkt[IPv6].dst
        if pkt.haslayer(ARP):
            return pkt[ARP].psrc, pkt[ARP].pdst
    except Exception:
        pass
    return None, None


def extract_ports(pkt: Packet) -> tuple[int | None, int | None]:
    """
    Extract source and destination transport ports from a packet.

    Checks TCP then UDP layers in priority order.

    Args:
        pkt: Scapy packet object.

    Returns:
        Tuple of (src_port, dst_port); both None for non-transport packets.
    """
    try:
        if pkt.haslayer(TCP):
            return pkt[TCP].sport, pkt[TCP].dport
        if pkt.haslayer(UDP):
            return pkt[UDP].sport, pkt[UDP].dport
    except Exception:
        pass
    return None, None


def extract_tcp_flags(pkt: Packet) -> TcpFlags | None:
    """
    Extract named TCP control flags from the TCP layer.

    Args:
        pkt: Scapy packet object.

    Returns:
        TcpFlags model, or None if no TCP layer is present.
    """
    try:
        if not pkt.haslayer(TCP):
            return None
        flags = pkt[TCP].flags
        return TcpFlags(
            syn=bool(flags & 0x02),
            ack=bool(flags & 0x10),
            fin=bool(flags & 0x01),
            rst=bool(flags & 0x04),
            psh=bool(flags & 0x08),
            urg=bool(flags & 0x20),
        )
    except Exception:
        return None


def extract_dns_fields(pkt: Packet) -> DnsFields | None:
    """
    Extract DNS query name and record type from the first DNSQR record.

    Args:
        pkt: Scapy packet object.

    Returns:
        DnsFields model, or None if no DNS query record is present.
    """
    try:
        if not pkt.haslayer(DNSQR):
            return None
        qr = pkt[DNSQR]
        query_name = (qr.qname or b"").decode("utf-8", "replace").rstrip(".")
        return DnsFields(query_name=query_name or None, record_type=int(qr.qtype))
    except Exception:
        return None


def extract_http_fields(pkt: Packet) -> HttpFields | None:
    """
    Extract HTTP/1.x request fields from the HTTPRequest Scapy layer.

    Args:
        pkt: Scapy packet object.

    Returns:
        HttpFields model, or None if no HTTPRequest layer is present.
    """
    try:
        if not pkt.haslayer(HTTPRequest):
            return None
        req = pkt[HTTPRequest]
        return HttpFields(
            method=(req.Method or b"").decode("utf-8", "replace") or None,
            path=(req.Path or b"").decode("utf-8", "replace") or None,
            host=(req.Host or b"").decode("utf-8", "replace") or None,
            user_agent=(req.User_Agent or b"").decode("utf-8", "replace") or None,
        )
    except Exception:
        return None


def extract_tls_fields(pkt: Packet) -> TlsFields | None:
    """
    Extract TLS ClientHello metadata (SNI + cipher suites) from a TCP payload.

    Performs metadata-only extraction — no key material, no decryption.

    Args:
        pkt: Scapy packet object.

    Returns:
        TlsFields model, or None if no TLS ClientHello is detected.
    """
    try:
        if not pkt.haslayer(TCP):
            return None
        raw = bytes(pkt[TCP].payload)
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
