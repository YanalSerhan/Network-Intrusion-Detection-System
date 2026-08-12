"""
Layer 3/4 field extraction.

Data Setup:  No state; pure functions over Scapy packets.
Data Input:  A Scapy Packet.
Data Output: Addresses, ports and TCP flags.

Split from application-layer extraction so a change to HTTP parsing cannot
affect the address path every packet takes.
"""

from scapy.layers.inet import IP, TCP, UDP  # type: ignore[import-untyped]
from scapy.layers.inet6 import IPv6  # type: ignore[import-untyped]
from scapy.layers.l2 import ARP  # type: ignore[import-untyped]
from scapy.packet import Packet  # type: ignore[import-untyped]

from .models import TcpFlags

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
