"""
Capture-layer packet filtering: BPF validation and protocol allow/deny lists.

Data Setup:  ProtocolFilterConfig injected at filter creation time.
Data Input:  A Scapy packet object and a ProtocolFilterConfig.
Data Output: Boolean pass/drop decision for each packet.
"""

from collections.abc import Callable

from scapy.layers.dns import DNS  # type: ignore[import-untyped]
from scapy.layers.http import HTTP  # type: ignore[import-untyped]
from scapy.layers.inet import ICMP, IP, TCP, UDP  # type: ignore[import-untyped]
from scapy.layers.inet6 import IPv6  # type: ignore[import-untyped]
from scapy.layers.l2 import ARP, Ether  # type: ignore[import-untyped]
from scapy.packet import Packet  # type: ignore[import-untyped]

from ..constants import Protocol
from .models import ProtocolFilterConfig

# Optional compile_filter — only available on Linux/macOS with libpcap.
# On Windows the function reference stays None and validation is skipped.
_compile_filter: Callable[..., object] | None = None
try:
    from scapy.arch import compile_filter as _cf  # type: ignore[import-untyped]

    _compile_filter = _cf
except ImportError:
    pass


def detect_protocol(pkt: Packet) -> str:
    """
    Detect the highest-layer protocol of a Scapy packet.

    Priority order (most specific first): DNS, HTTP, TLS, TCP, UDP, ICMP,
    ARP, IPv6, IPv4, Ethernet.

    Args:
        pkt: A Scapy packet object.

    Returns:
        A Protocol enum value string (e.g. 'tcp', 'dns').
    """
    if pkt.haslayer(DNS):
        return Protocol.DNS
    if pkt.haslayer(HTTP):
        return Protocol.HTTP
    # TLS detection: TCP payload starting with content-type 0x16 (handshake/app-data)
    if pkt.haslayer(TCP):
        tcp_layer = pkt[TCP]
        raw = bytes(tcp_layer.payload)
        if len(raw) >= 3 and raw[0] == 0x16:
            return Protocol.TLS
    if pkt.haslayer(TCP):
        return Protocol.TCP
    if pkt.haslayer(UDP):
        return Protocol.UDP
    if pkt.haslayer(ICMP):
        return Protocol.ICMP
    if pkt.haslayer(ARP):
        return Protocol.ARP
    if pkt.haslayer(IPv6):
        return Protocol.IPV6
    if pkt.haslayer(IP):
        return Protocol.IP
    if pkt.haslayer(Ether):
        return Protocol.ETHERNET
    return Protocol.UNKNOWN


def apply_protocol_filter(pkt: Packet, filter_cfg: ProtocolFilterConfig) -> bool:
    """
    Decide whether a packet should be passed downstream.

    Rules (applied in order):
      1. If the protocol is in deny_list  → drop (return False).
      2. If allow_list is non-empty and protocol NOT in allow_list → drop.
      3. Otherwise → pass (return True).

    Args:
        pkt:        Scapy packet to evaluate.
        filter_cfg: Allow/deny configuration.

    Returns:
        True if the packet passes the filter; False if it should be dropped.
    """
    protocol = detect_protocol(pkt)

    if protocol in filter_cfg.deny_list:
        return False

    return not filter_cfg.allow_list or protocol in filter_cfg.allow_list



def validate_bpf_filter(expr: str) -> bool:
    """
    Validate a BPF filter expression without capturing any packets.

    Uses Scapy's compile_filter when available (Linux/macOS with libpcap).
    On Windows — where compile_filter is absent — any non-empty string is
    accepted as valid; Scapy will raise at capture time if the filter is bad.

    Args:
        expr: BPF filter string (e.g. 'tcp port 80').

    Returns:
        True if the expression is accepted as valid; False otherwise.
    """
    if not expr:
        return True  # empty = no filter, always valid

    if _compile_filter is None:
        # compile_filter unavailable on this platform; optimistically accept.
        return True

    try:
        _compile_filter(expr)
        return True
    except Exception:
        return False
