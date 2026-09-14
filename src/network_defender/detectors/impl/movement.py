"""
Data exfiltration and lateral movement detectors.

Grouped because both accumulate per-source volume over a window and threshold
it, rather than matching any single packet.

Data Setup:  Thresholds from config/detectors.json.
Data Input:  Parsed packets.
Data Output: Alerts for large outbound volume and internal-to-internal fan-out.
"""

import ipaddress

from pydantic import Field

from network_defender.constants import MitreTactic, Severity
from network_defender.detectors.models import DetectorConfig
from network_defender.parser.models import ParsedPacket

from .breadth import BreadthDetector
from .counting_endpoints import SourceCountingDetector


class DataExfiltrationConfig(DetectorConfig):
    """Tunables for the data exfiltration detector."""

    time_window_seconds: int = Field(default=60)
    bytes_out_threshold: int = Field(default=50_000_000)

class DataExfiltrationDetector(SourceCountingDetector[DataExfiltrationConfig]):
    """
    Detects one host pushing an unusual volume of data outbound.

    Volume alone, with no opinion on where it went: a backup to cloud storage
    and a staged archive leaving for an attacker look identical on the wire,
    and deciding between them needs context a sensor does not have. The
    threshold is high on purpose — this is a detector that earns its place by
    rarely firing, and the alert it does raise is worth a human's time.

    A counting detector whose `amount` is bytes rather than one. It kept its
    own copy of the tally-and-threshold loop until Milestone 21, which is the
    same duplication `counting` was extracted to remove — it was missed
    because counting packets and counting bytes did not look like the same
    thing until the window needed fixing in both.
    """

    evidence_key = "bytes_out"
    severity = Severity.CRITICAL
    tactic = MitreTactic.EXFILTRATION

    @property
    def name(self) -> str:
        """Detector name used in alerts and configuration."""
        return "DataExfiltrationDetector"

    @property
    def threshold(self) -> int:
        """Bytes per window at or above which to report."""
        return self.config.bytes_out_threshold

    def counts(self, packet: ParsedPacket) -> bool:
        """Return True for anything with a source to attribute the bytes to."""
        return bool(packet.src_ip)

    def amount(self, packet: ParsedPacket) -> int:
        """Bytes, not arrivals: the measurement is volume."""
        return packet.length

    def describe(self, count: int) -> str:
        """Describe the transfer for the analyst reading the alert."""
        return f"Large Data Exfiltration: {count} bytes sent."


class LateralMovementConfig(DetectorConfig):
    """Tunables for the lateral movement detector."""

    time_window_seconds: int = Field(default=60)
    internal_connection_threshold: int = Field(default=20)

class LateralMovementDetector(BreadthDetector[LateralMovementConfig]):
    """
    Detects one internal host reaching an unusual number of internal peers.

    Fan-out is the signal, not volume: a workstation talks to a handful of
    servers, while a compromised host looking for somewhere to go next talks
    to everything. Both endpoints must be internal, which is what separates
    this from a port scan arriving from outside.
    """

    evidence_key = "unique_internal_destinations"
    severity = Severity.HIGH
    tactic = MitreTactic.LATERAL_MOVEMENT

    @property
    def name(self) -> str:
        """Detector name used in alerts and configuration."""
        return "LateralMovementDetector"

    @property
    def threshold(self) -> int:
        """Distinct internal peers per window at or above which to report."""
        return self.config.internal_connection_threshold

    def _is_internal(self, ip: str) -> bool:
        """
        Return True if the address belongs to a private range.

        Uses the stdlib parser rather than string prefixes: prefix matching
        raised on malformed input (e.g. "172." -> IndexError), misread
        addresses such as "172.5.0.1" as internal-adjacent, and ignored IPv6
        unique-local space entirely, even though the PRD puts IPv6 in scope.
        """
        try:
            return ipaddress.ip_address(ip).is_private
        except ValueError:
            return False

    def counts(self, packet: ParsedPacket) -> bool:
        """Return True only when both ends of the conversation are internal."""
        return bool(
            packet.src_ip
            and packet.dst_ip
            and self._is_internal(packet.src_ip)
            and self._is_internal(packet.dst_ip)
        )

    def peer(self, packet: ParsedPacket) -> str | None:
        """An internal host is the unit of breadth for lateral movement."""
        return packet.dst_ip

    def describe(self, count: int) -> str:
        """Describe the fan-out for the analyst reading the alert."""
        return f"Suspicious Lateral Movement: connected to {count} internal hosts."
