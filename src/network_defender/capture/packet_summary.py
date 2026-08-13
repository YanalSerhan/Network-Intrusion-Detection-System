"""
Human-readable packet summary builder.

Data Setup:  No external configuration required.
Data Input:  A Scapy packet object.
Data Output: A populated PacketSummary Pydantic model.

Supported protocols, highest layer wins: TLS, DNS, HTTP, TCP, UDP, ICMP, ARP,
IPv6, IPv4, Ethernet. TLS metadata extraction lives in `tls_metadata`.
"""

from datetime import UTC, datetime

from scapy.layers.dns import DNSQR
from scapy.layers.http import HTTPRequest
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.inet6 import IPv6
from scapy.layers.l2 import ARP
from scapy.packet import Packet

from ..constants import Protocol
from .filters import detect_protocol
from .models import PacketSummary
from .tls_metadata import extract_tls_metadata


def summarise_packet(packet: Packet) -> PacketSummary:
    """
    Build a human-readable PacketSummary from a Scapy packet.

    Args:
        packet: Any Scapy packet (Ethernet, IP, raw, etc.).

    Returns:
        Populated PacketSummary with all available fields set.
    """
    timestamp = datetime.fromtimestamp(float(packet.time), tz=UTC)
    length = len(packet)
    protocol = detect_protocol(packet)

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
    if packet.haslayer(IP):
        src_ip, dst_ip = packet[IP].src, packet[IP].dst
    elif packet.haslayer(IPv6):
        src_ip, dst_ip = packet[IPv6].src, packet[IPv6].dst
    elif packet.haslayer(ARP):
        src_ip, dst_ip = packet[ARP].psrc, packet[ARP].pdst

    # Transport ports
    if packet.haslayer(TCP):
        src_port, dst_port = packet[TCP].sport, packet[TCP].dport
    elif packet.haslayer(UDP):
        src_port, dst_port = packet[UDP].sport, packet[UDP].dport

    # Protocol-specific extraction
    if protocol == Protocol.DNS and packet.haslayer(DNSQR):
        dns_query = packet[DNSQR].qname.decode("utf-8", "replace").rstrip(".")
    elif protocol == Protocol.HTTP and packet.haslayer(HTTPRequest):
        req = packet[HTTPRequest]
        http_method = (req.Method or b"").decode("utf-8", "replace")
        http_path = (req.Path or b"").decode("utf-8", "replace")
        http_host = (req.Host or b"").decode("utf-8", "replace")
        http_ua = (req.User_Agent or b"").decode("utf-8", "replace") or None
    elif protocol == Protocol.TLS and packet.haslayer(TCP):
        tls_sni, tls_ciphers = extract_tls_metadata(packet)

    summary_str = (
        f"{protocol} {src_ip or '?'}:{src_port or '?'} → {dst_ip or '?'}:{dst_port or '?'} "
        f"len={length}"
    )

    return PacketSummary(
        timestamp=timestamp,
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
