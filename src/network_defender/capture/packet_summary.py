"""
Human-readable packet summary builder.

Data Setup:  No external configuration required.
Data Input:  A Scapy packet object.
Data Output: A populated PacketSummary Pydantic model.

Supported protocols (highest-layer wins):
  TLS (ClientHello SNI + cipher suites), DNS (query extraction),
  HTTP (method, path, Host, User-Agent), TCP, UDP, ICMP,
  ARP, IPv6, IPv4, Ethernet.

No decryption is performed for TLS — only metadata from the ClientHello
handshake message is extracted.
"""

from datetime import UTC, datetime

from scapy.layers.dns import DNSQR  # type: ignore[import-untyped]
from scapy.layers.http import HTTPRequest  # type: ignore[import-untyped]
from scapy.layers.inet import IP, TCP, UDP  # type: ignore[import-untyped]
from scapy.layers.inet6 import IPv6  # type: ignore[import-untyped]
from scapy.layers.l2 import ARP  # type: ignore[import-untyped]
from scapy.packet import Packet  # type: ignore[import-untyped]

from ..constants import Protocol, TlsHandshakeType
from .filters import detect_protocol
from .models import PacketSummary

# TLS record content-type for handshake messages
_TLS_CONTENT_TYPE_HANDSHAKE = 0x16
_TLS_SNI_TYPE = 0x00  # server_name extension type


def _extract_tls_metadata(pkt: Packet) -> tuple[str | None, list[int] | None]:
    """
    Parse TLS ClientHello for SNI hostname and offered cipher suite IDs.

    Extracts metadata only — no key material, no decryption.

    Args:
        pkt: Scapy packet with a TCP layer whose payload starts with a TLS record.

    Returns:
        Tuple of (sni_hostname | None, cipher_suite_ids | None).
    """
    try:
        raw = bytes(pkt[TCP].payload)
        # TLS record: content_type(1) + version(2) + length(2) + handshake
        if len(raw) < 6 or raw[0] != _TLS_CONTENT_TYPE_HANDSHAKE:
            return None, None
        # Handshake header: type(1) + length(3)
        if raw[5] != TlsHandshakeType.CLIENT_HELLO:
            return None, None

        offset = 9  # skip record header (5) + handshake type (1) + length (3)
        offset += 2  # client version
        offset += 32  # random
        session_id_len = raw[offset]
        offset += 1 + session_id_len
        cipher_len = int.from_bytes(raw[offset : offset + 2], "big")
        offset += 2
        cipher_suites = [
            int.from_bytes(raw[offset + i : offset + i + 2], "big")
            for i in range(0, cipher_len, 2)
        ]
        offset += cipher_len
        offset += 1 + raw[offset]  # compression methods
        if offset + 2 > len(raw):
            return None, cipher_suites
        ext_total = int.from_bytes(raw[offset : offset + 2], "big")
        offset += 2
        end = offset + ext_total
        sni: str | None = None
        while offset + 4 <= end:
            ext_type = int.from_bytes(raw[offset : offset + 2], "big")
            ext_len = int.from_bytes(raw[offset + 2 : offset + 4], "big")
            offset += 4
            if ext_type == _TLS_SNI_TYPE and offset + ext_len <= end:
                # SNI list: list_len(2) + type(1) + name_len(2) + name
                name_offset = offset + 3
                name_len = int.from_bytes(raw[offset + 3 : offset + 5], "big")
                sni = raw[name_offset + 2 : name_offset + 2 + name_len].decode("utf-8", "replace")
                break
            offset += ext_len
        return sni, cipher_suites
    except Exception:
        return None, None


def summarise_packet(pkt: Packet) -> PacketSummary:
    """
    Build a human-readable PacketSummary from a Scapy packet.

    Args:
        pkt: Any Scapy packet (Ethernet, IP, raw, etc.).

    Returns:
        Populated PacketSummary with all available fields set.
    """
    ts = datetime.fromtimestamp(float(pkt.time), tz=UTC)
    length = len(pkt)
    protocol = detect_protocol(pkt)

    src_ip: str | None = None
    dst_ip: str | None = None
    src_port: int | None = None
    dst_port: int | None = None
    dns_query: str | None = None
    http_method: str | None = None
    http_host: str | None = None
    http_path: str | None = None
    http_ua: str | None = None
    tls_sni: str | None = None
    tls_ciphers: list[int] | None = None

    # IP addressing
    if pkt.haslayer(IP):
        src_ip, dst_ip = pkt[IP].src, pkt[IP].dst
    elif pkt.haslayer(IPv6):
        src_ip, dst_ip = pkt[IPv6].src, pkt[IPv6].dst
    elif pkt.haslayer(ARP):
        src_ip, dst_ip = pkt[ARP].psrc, pkt[ARP].pdst

    # Transport ports
    if pkt.haslayer(TCP):
        src_port, dst_port = pkt[TCP].sport, pkt[TCP].dport
    elif pkt.haslayer(UDP):
        src_port, dst_port = pkt[UDP].sport, pkt[UDP].dport

    # Protocol-specific extraction
    if protocol == Protocol.DNS and pkt.haslayer(DNSQR):
        dns_query = pkt[DNSQR].qname.decode("utf-8", "replace").rstrip(".")
    elif protocol == Protocol.HTTP and pkt.haslayer(HTTPRequest):
        req = pkt[HTTPRequest]
        http_method = (req.Method or b"").decode("utf-8", "replace")
        http_path = (req.Path or b"").decode("utf-8", "replace")
        http_host = (req.Host or b"").decode("utf-8", "replace")
        http_ua = (req.User_Agent or b"").decode("utf-8", "replace") or None
    elif protocol == Protocol.TLS and pkt.haslayer(TCP):
        tls_sni, tls_ciphers = _extract_tls_metadata(pkt)

    summary_str = (
        f"{protocol} {src_ip or '?'}:{src_port or '?'} → {dst_ip or '?'}:{dst_port or '?'} "
        f"len={length}"
    )

    return PacketSummary(
        timestamp=ts,
        protocol=protocol,
        src_ip=src_ip,
        dst_ip=dst_ip,
        src_port=src_port,
        dst_port=dst_port,
        length=length,
        summary=summary_str,
        dns_query=dns_query,
        http_method=http_method,
        http_host=http_host,
        http_path=http_path,
        http_user_agent=http_ua,
        tls_sni=tls_sni,
        tls_cipher_suites=tls_ciphers,
    )
