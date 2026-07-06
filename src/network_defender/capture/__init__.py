"""
Capture package for Network Defender.

Public API re-exported here for clean external imports:

    from network_defender.capture import CaptureService, CaptureStatus

Data Input:  Raw packets from a live network interface or PCAP file.
Data Output: Structured PacketSummary objects and CaptureStatus snapshots.
Data Setup:  CaptureConfig injected into CaptureService constructor.
"""

from .models import CaptureStatus, PacketSummary, ProtocolFilterConfig
from .service import CaptureService

__all__ = [
    "CaptureService",
    "CaptureStatus",
    "PacketSummary",
    "ProtocolFilterConfig",
]
