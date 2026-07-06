"""
PacketParser — normalises raw Scapy packets into ParsedPacket models.

Data Setup:  No external configuration required; instantiated once at startup.
Data Input:  Raw Scapy Packet objects from the CaptureService callback.
Data Output: ParsedPacket Pydantic models consumed by the Detection Engine.

Architecture:
  - Extends BaseService (start/stop/health lifecycle) and ValidatableMixin.
  - All extraction logic is delegated to extractors.py (single-responsibility).
  - parse_safe() catches any unexpected exception so the caller never crashes.
  - summarise_packet() from the capture layer provides the raw_summary string,
    avoiding duplication of the one-line description logic.
"""

from datetime import UTC, datetime
from typing import Any

from scapy.packet import Packet  # type: ignore[import-untyped]

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

    Data Setup:  No injected config; constructed with no arguments.
    Data Input:  Scapy Packet objects (live or from PCAP replay).
    Data Output: ParsedPacket models ready for the Detection Engine.
    """

    def __init__(self) -> None:
        """Initialise the PacketParser with no external dependencies."""
        super().__init__(service_name="PacketParser")
        self._packets_parsed: int = 0
        self._packets_failed: int = 0

    # ------------------------------------------------------------------
    # ValidatableMixin
    # ------------------------------------------------------------------

    def validate(self, data: Any) -> bool:
        """
        Check that the input is a non-None Scapy Packet before parsing.

        Args:
            data: The value to validate (expected to be a Packet).

        Returns:
            True if data is a valid Packet; False otherwise.
        """
        return data is not None and isinstance(data, Packet)

    # ------------------------------------------------------------------
    # Public parse API
    # ------------------------------------------------------------------

    def parse(self, pkt: Packet) -> ParsedPacket:
        """
        Parse a Scapy packet into a normalised ParsedPacket.

        Args:
            pkt: A Scapy Packet object (must not be None).

        Returns:
            Populated ParsedPacket model.

        Raises:
            ValueError: If pkt fails validation.
        """
        if not self.validate(pkt):
            raise ValueError("PacketParser.parse() received an invalid packet.")

        ts = datetime.fromtimestamp(float(pkt.time), tz=UTC)
        protocol = detect_protocol(pkt)
        length = len(pkt)
        src_ip, dst_ip = extract_ip_addresses(pkt)
        src_port, dst_port = extract_ports(pkt)
        tcp_flags = extract_tcp_flags(pkt)
        dns = extract_dns_fields(pkt)
        http = extract_http_fields(pkt)
        tls = extract_tls_fields(pkt)
        raw_summary = summarise_packet(pkt).summary

        self._packets_parsed += 1
        return ParsedPacket(
            timestamp=ts,
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

    def parse_safe(self, pkt: Packet) -> ParsedPacket | None:
        """
        Parse a packet, returning None instead of raising on any failure.

        Args:
            pkt: A Scapy Packet object.

        Returns:
            ParsedPacket on success; None on validation failure or exception.
        """
        try:
            return self.parse(pkt)
        except Exception as exc:
            self._packets_failed += 1
            self.logger.warning("parse_safe: failed to parse packet — %s", exc)
            return None

    # ------------------------------------------------------------------
    # BaseService hooks
    # ------------------------------------------------------------------

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
