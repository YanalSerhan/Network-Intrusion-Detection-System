"""
Capture-layer packet filtering: BPF validation and protocol allow/deny lists.

Data Setup:  ProtocolFilterConfig injected at filter creation time.
Data Input:  A Scapy packet object and a ProtocolFilterConfig.
Data Output: Boolean pass/drop decision for each packet.
"""

from collections.abc import Callable

from scapy.layers.dns import DNS
from scapy.layers.http import HTTP
from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.layers.inet6 import IPv6
from scapy.layers.l2 import ARP, Ether
from scapy.packet import Packet

from ..constants import Protocol
from .models import ProtocolFilterConfig

# Optional compile_filter — only available on Linux/macOS with libpcap.
# On Windows the function reference stays None and validation is skipped.
_compile_filter: Callable[..., object] | None = None
try:
    from scapy.arch import compile_filter as _cf

    _compile_filter = _cf
except ImportError:
    pass


#: Scapy layer -> the protocol it identifies, most specific first. A table
#: rather than a chain of branches: the priority order *is* the data, and
#: reading it top to bottom is how you check that DNS beats UDP.
_LAYER_PROTOCOLS: tuple[tuple[type[Packet], str], ...] = (
    (DNS, Protocol.DNS),
    (HTTP, Protocol.HTTP),
    (TCP, Protocol.TCP),
    (UDP, Protocol.UDP),
    (ICMP, Protocol.ICMP),
    (ARP, Protocol.ARP),
    (IPv6, Protocol.IPV6),
    (IP, Protocol.IP),
    (Ether, Protocol.ETHERNET),
)

#: TLS record content type for a handshake message, and the smallest record
#: header worth inspecting. Scapy's TLS layer is optional, so TLS is
#: recognised from the first bytes of the TCP payload instead.
_TLS_HANDSHAKE_CONTENT_TYPE = 0x16
_TLS_MIN_RECORD_BYTES = 3


def _is_tls(packet: Packet) -> bool:
    """
    Return True if the TCP payload opens with a TLS handshake record.

    Args:
        packet: A Scapy packet already known to carry TCP.

    Returns:
        Whether the payload looks like TLS.
    """
    raw = bytes(packet[TCP].payload)
    return len(raw) >= _TLS_MIN_RECORD_BYTES and raw[0] == _TLS_HANDSHAKE_CONTENT_TYPE


def detect_protocol(packet: Packet) -> str:
    """
    Detect the highest-layer protocol of a Scapy packet.

    Args:
        packet: A Scapy packet object.

    Returns:
        A Protocol enum value string (e.g. 'tcp', 'dns').
    """
    if packet.haslayer(TCP) and _is_tls(packet):
        return Protocol.TLS
    for layer, protocol in _LAYER_PROTOCOLS:
        if packet.haslayer(layer):
            return protocol
    return Protocol.UNKNOWN


def apply_protocol_filter(packet: Packet, filter_cfg: ProtocolFilterConfig) -> bool:
    """
    Decide whether a packet should be passed downstream.

    Rules (applied in order):
      1. If the protocol is in deny_list  → drop (return False).
      2. If allow_list is non-empty and protocol NOT in allow_list → drop.
      3. Otherwise → pass (return True).

    Args:
        packet:        Scapy packet to evaluate.
        filter_cfg: Allow/deny configuration.

    Returns:
        True if the packet passes the filter; False if it should be dropped.
    """
    protocol = detect_protocol(packet)

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
