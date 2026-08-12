"""
PCAP file replay and capture export.

Data Setup:  Expects the composing class to own the packet callback, filters
             and captured-packet buffer.
Data Input:  A .pcap path to replay, or a destination to write.
Data Output: Packets pushed through the normal callback path; PCAP files.

Replay deliberately reuses the live callback rather than a separate path, so
offline analysis exercises exactly the filters and rate limiting that live
capture does — a PCAP that triggers an alert offline will trigger it on the
wire too.
"""

from pathlib import Path
from typing import Any

from scapy.packet import Packet  # type: ignore[import-untyped]

from .pcap_io import read_pcap, write_pcap


class PcapReplayMixin:
    """PCAP replay and export for the capture service."""

    _is_pcap_mode: bool
    _lock: Any
    _captured_packets: list[Packet]

    def start_pcap_replay(self, path: str | Path) -> None:
        """
        Replay packets from a PCAP file through the normal callback pipeline.

        Args:
            path: Path to the .pcap file.
        """
        self._is_pcap_mode = True
        for packet in read_pcap(path):
            self._on_packet(packet)  # type: ignore[attr-defined]

    def save_to_pcap(self, path: str | Path) -> None:
        """
        Save packets captured in this session to a PCAP file.

        Args:
            path: Destination file path.
        """
        with self._lock:
            snapshot = list(self._captured_packets)
        write_pcap(snapshot, path)
        self.logger.info(  # type: ignore[attr-defined]
            "Saved %d packets to '%s'.", len(snapshot), path
        )
