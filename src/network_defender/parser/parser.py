"""
PacketParser — normalises raw Scapy packets into ParsedPacket models.

Data Setup:  No external configuration required; instantiated once at startup.
Data Input:  Raw Scapy Packet objects from the CaptureService callback.
Data Output: ParsedPacket Pydantic models consumed by the Detection Engine.

Field extraction is delegated to `extractors`; the one-line description reuses
`summarise_packet` from the capture layer. `parse_safe()` swallows any
unexpected exception so a single malformed packet never stops the pipeline.
"""

from datetime import UTC, datetime
from typing import Any

from scapy.packet import Packet

from ..capture.filters import detect_protocol
from ..capture.packet_summary import summarise_packet
from ..shared.base import BaseService, ValidatableMixin
from .extractors import (
    extract_dns_fields,
    extract_http_fields,
    extract_ip_addresses,
    extract_ports,
    extract_tcp_flags,
    extract_tls_fields,
)
from .models import ParsedPacket


class PacketParser(BaseService, ValidatableMixin):
    """
    Converts raw Scapy packets into normalised ParsedPacket models.

    Consumers call parse() (raises on error) or parse_safe() (returns None).
    The parser must be started before parsing; use start()/stop() from BaseService.
    """

    def __init__(self) -> None:
        """Initialise the PacketParser with no external dependencies."""
        super().__init__(service_name="PacketParser")
        self._packets_parsed: int = 0
        self._packets_failed: int = 0

    def validate(self, data: Any) -> bool:
        """
        Check that the input is a non-None Scapy Packet before parsing.

        Args:
            data: The value to validate (expected to be a Packet).

        Returns:
            True if data is a valid Packet; False otherwise.
        """
        return data is not None and isinstance(data, Packet)

    def parse(self, packet: Packet) -> ParsedPacket:
        """
        Parse a Scapy packet into a normalised ParsedPacket.

        Args:
            packet: A Scapy Packet object (must not be None).

        Returns:
            Populated ParsedPacket model.

        Raises:
            ValueError: If packet fails validation.
        """
        if not self.validate(packet):
            raise ValueError("PacketParser.parse() received an invalid packet.")

        timestamp = datetime.fromtimestamp(float(packet.time), tz=UTC)
        protocol = detect_protocol(packet)
        length = len(packet)
        src_ip, dst_ip = extract_ip_addresses(packet)
        src_port, dst_port = extract_ports(packet)
        tcp_flags = extract_tcp_flags(packet)
        dns = extract_dns_fields(packet)
        http = extract_http_fields(packet)
        tls = extract_tls_fields(packet)
        raw_summary = summarise_packet(packet).summary

        self._packets_parsed += 1
        return ParsedPacket(
            timestamp=timestamp,
            src_ip=src_ip,
            dst_ip=dst_ip,
            src_port=src_port,
            dst_port=dst_port,
            protocol=protocol,
            length=length,
            tcp_flags=tcp_flags,
            dns=dns,
            http=http,
            tls=tls,
            raw_summary=raw_summary,
        )

    def parse_safe(self, packet: Packet) -> ParsedPacket | None:
        """
        Parse a packet, returning None instead of raising on any failure.

        Args:
            packet: A Scapy Packet object.

        Returns:
            ParsedPacket on success; None on validation failure or exception.
        """
        try:
            return self.parse(packet)
        except Exception as exc:
            self._packets_failed += 1
            self.logger.warning("parse_safe: failed to parse packet — %s", exc)
            return None

    def _do_start(self) -> None:
        """Reset counters and mark the parser as ready."""
        self._packets_parsed = 0
        self._packets_failed = 0
        self.logger.info("PacketParser ready.")

    def _do_stop(self) -> None:
        """Log final counters on shutdown."""
        self.logger.info(
            "PacketParser stopped. parsed=%d failed=%d",
            self._packets_parsed,
            self._packets_failed,
        )

    def _do_health_check(self) -> dict[str, Any]:
        """Return parser-specific health metrics."""
        return {
            "packets_parsed": self._packets_parsed,
            "packets_failed": self._packets_failed,
        }
