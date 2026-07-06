"""
Parser package for Network Defender.

Public API re-exported here for clean external imports:

    from network_defender.parser import PacketParser, ParsedPacket

Data Input:  Raw Scapy Packet objects from the CaptureService.
Data Output: ParsedPacket models consumed by the Detection Engine.
Data Setup:  PacketParser requires no external configuration.
"""

from .models import DnsFields, HttpFields, ParsedPacket, TcpFlags, TlsFields
from .parser import PacketParser

__all__ = [
    "PacketParser",
    "ParsedPacket",
    "TcpFlags",
    "DnsFields",
    "HttpFields",
    "TlsFields",
]
