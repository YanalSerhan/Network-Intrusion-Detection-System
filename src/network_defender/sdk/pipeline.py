"""
End-to-end packet pipeline wiring.

Data Setup:  Expects the composing class to own the capture, parser, detection
             and alert services.
Data Input:  Raw Scapy packets delivered by the capture service callback.
Data Output: Parsed packets pushed into the detection service, whose alerts
             flow on to the alert service.

Why this exists
---------------
Capture, parsing, detection and alerting were each implemented and individually
tested, but nothing connected them: the capture callback was never registered,
so packets were counted and discarded and no detector ever saw traffic. This
mixin installs the missing link:

    NIC -> CaptureService -> PacketParser -> DetectionService -> AlertService
"""

from scapy.packet import Packet  # type: ignore[import-untyped]

from ..parser.models import ParsedPacket
from ..rules.models import Rule
from ..services.alerts import AlertService
from ..services.capture import CaptureService
from ..services.detection import DetectionService
from ..services.parser import PacketParser
from ..shared.base import LoggableMixin


class PipelineMixin(LoggableMixin):
    """Connects capture output to parsing, detection and alerting."""

    _capture_service: CaptureService
    _parser_service: PacketParser
    _detection_service: DetectionService
    _alert_service: AlertService

    def _wire_pipeline(self) -> None:
        """Register the capture callback that drives the whole pipeline."""
        self._capture_service.set_packet_callback(self._on_raw_packet)

    def _on_raw_packet(self, pkt: Packet) -> None:
        """
        Parse a captured packet and hand it to the detection service.

        Uses the non-raising parser path: a single malformed packet must never
        interrupt a live capture.

        Args:
            pkt: Raw Scapy packet admitted by the capture filters.
        """
        parsed = self._parser_service.parse_safe(pkt)
        if parsed is None:
            return
        self._detection_service.process_packet(parsed)

    def _on_rule_match(self, rule: Rule, packet: ParsedPacket) -> None:
        """
        Route a signature rule match into the alert pipeline.

        Args:
            rule:   The rule whose conditions all matched.
            packet: The packet that satisfied them.
        """
        self._alert_service.handle_rule_match(rule, packet)
