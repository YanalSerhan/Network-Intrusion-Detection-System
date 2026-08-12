"""
Packet field extraction.

Re-exports the layer 3/4 and layer 7 extractors so callers keep a single import
site while each layer lives in its own module (ADR 4).

Data Setup:  No state; pure functions over Scapy packets.
Data Input:  A Scapy Packet.
Data Output: Typed field values for ParsedPacket.
"""

from .application_extractors import (
    extract_dns_fields,
    extract_http_fields,
    extract_tls_fields,
)
from .transport_extractors import (
    extract_ip_addresses,
    extract_ports,
    extract_tcp_flags,
)

__all__ = [
    "extract_dns_fields",
    "extract_http_fields",
    "extract_ip_addresses",
    "extract_ports",
    "extract_tcp_flags",
    "extract_tls_fields",
]
