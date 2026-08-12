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
        tls_sni, tls_ciphers = extract_tls_metadata(pkt)

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
