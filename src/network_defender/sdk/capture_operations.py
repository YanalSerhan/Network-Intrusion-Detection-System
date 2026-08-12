"""
Capture, parsing and gatekeeper SDK operations.

Data Setup:  Expects the composing class to own the capture and parser services
             plus the gatekeeper registry.
Data Input:  Interface and PCAP paths, raw Scapy packets.
Data Output: Capture status, parsed packets, gatekeeper handles.
"""

from pathlib import Path

from scapy.packet import Packet

from ..capture.interface_discovery import list_interfaces
from ..capture.models import CaptureStatus
from ..parser.models import ParsedPacket
from ..services.capture import CaptureService
from ..services.parser import PacketParser
from ..shared.gatekeeper import ApiGatekeeper


class CaptureOperationsMixin:
    """Capture, parsing and outbound-gatekeeper surface of the SDK."""

    _capture_service: CaptureService
    _parser_service: PacketParser
    _gatekeepers: dict[str, ApiGatekeeper]

    def start_capture(self) -> None:
        """Start live packet capture on the configured interface."""
        self._capture_service.start()

    def stop_capture(self) -> None:
        """Stop the active live capture session."""
        self._capture_service.stop()

    def start_capture_from_pcap(self, path: str | Path) -> None:
        """
        Replay a PCAP file through the full detection pipeline.

        Args:
            path: Path to the .pcap file.
        """
        self._capture_service.start_pcap_replay(path)

    def save_capture_to_pcap(self, path: str | Path) -> None:
        """
        Save packets captured this session to a PCAP file.

        Args:
            path: Destination file path.
        """
        self._capture_service.save_to_pcap(path)

    def get_capture_status(self) -> CaptureStatus:
        """Return a snapshot of the capture service's current state."""
        return self._capture_service.get_status()

    def list_interfaces(self) -> list[str]:
        """Return the sorted list of interfaces visible to Scapy."""
        return list_interfaces()

    def parse_packet(self, pkt: Packet) -> ParsedPacket:
        """
        Parse a raw Scapy packet into a normalised ParsedPacket.

        Args:
            pkt: A Scapy Packet captured by CaptureService.

        Returns:
            ParsedPacket with all available protocol fields populated.

        Raises:
            ValueError: If pkt is not a valid Packet.
        """
        return self._parser_service.parse(pkt)

    def parse_packet_safe(self, pkt: Packet) -> ParsedPacket | None:
        """
        Parse a packet without raising, returning None on any failure.

        For high-throughput capture callbacks, where one malformed packet must
        not interrupt the pipeline.

        Args:
            pkt: A Scapy Packet.

        Returns:
            ParsedPacket on success; None if parsing fails.
        """
        return self._parser_service.parse_safe(pkt)

    def get_gatekeeper(self, service_name: str) -> ApiGatekeeper:
        """
        Retrieve the gatekeeper for a named external service.

        Args:
            service_name: Must match a key in config/rate_limits.json.

        Returns:
            The ApiGatekeeper for that service.

        Raises:
            KeyError: If the service has no configured rate limits.
        """
        if service_name not in self._gatekeepers:
            raise KeyError(
                f"No gatekeeper configured for service '{service_name}'. "
                f"Available: {list(self._gatekeepers)}"
            )
        return self._gatekeepers[service_name]
