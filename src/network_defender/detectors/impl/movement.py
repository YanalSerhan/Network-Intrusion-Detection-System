"""
Data exfiltration and lateral movement detectors.

Grouped because both accumulate per-source volume over a window and threshold
it, rather than matching any single packet.

Data Setup:  Thresholds from config/detectors.json.
Data Input:  Parsed packets.
Data Output: Alerts for large outbound volume and internal-to-internal fan-out.
"""

import ipaddress
from collections import defaultdict

from pydantic import Field

from network_defender.constants import MitreTactic, Severity
from network_defender.detectors.base import BaseDetector
from network_defender.detectors.models import DetectionAlert, DetectorConfig
from network_defender.parser.models import ParsedPacket


class DataExfiltrationConfig(DetectorConfig):
    """Tunables for the data exfiltration detector."""

    time_window_seconds: int = Field(default=60)
    bytes_out_threshold: int = Field(default=50_000_000)

class DataExfiltrationDetector(BaseDetector[DataExfiltrationConfig]):
    """
    Detects one host pushing an unusual volume of data outbound.

    Volume alone, with no opinion on where it went: a backup to cloud storage
    and a staged archive leaving for an attacker look identical on the wire,
    and deciding between them needs context a sensor does not have. The
    threshold is high on purpose — this is a detector that earns its place by
    rarely firing, and the alert it does raise is worth a human's time.
    """

    def __init__(self, config: DataExfiltrationConfig) -> None:
        """Initialise with the validated outbound-byte threshold."""
        super().__init__(config)
        self._src_bytes: defaultdict[str, int] = defaultdict(int)

    @property
    def name(self) -> str:
        """Detector name used in alerts and configuration."""
        return "DataExfiltrationDetector"

    def ingest(self, packet: ParsedPacket) -> None:
        """Add this packet's length to its source's running total."""
        if packet.src_ip:
            self._src_bytes[packet.src_ip] += packet.length

    def evaluate(self) -> list[DetectionAlert]:
        """Emit an alert per over-sending source, then clear the window."""
        alerts = []
        for src_ip, bytes_out in self._src_bytes.items():
            if bytes_out >= self.config.bytes_out_threshold:
                alerts.append(
                    self.emit_alert(
                        severity=Severity.CRITICAL,
                        tactic=MitreTactic.EXFILTRATION,
                        src_ip=src_ip,
                        description=f"Large Data Exfiltration: {bytes_out} bytes sent.",
                        evidence={"bytes_out": bytes_out}
                    )
                )
        self._src_bytes.clear()
        return alerts


class LateralMovementConfig(DetectorConfig):
    """Tunables for the lateral movement detector."""

    time_window_seconds: int = Field(default=60)
    internal_connection_threshold: int = Field(default=20)

class LateralMovementDetector(BaseDetector[LateralMovementConfig]):
    """
    Detects one internal host reaching an unusual number of internal peers.

    Fan-out is the signal, not volume: a workstation talks to a handful of
    servers, while a compromised host looking for somewhere to go next talks
    to everything. Both endpoints must be internal, which is what separates
    this from a port scan arriving from outside.
    """

    def __init__(self, config: LateralMovementConfig) -> None:
        """Initialise with the validated internal-peer threshold."""
        super().__init__(config)
        self._src_dst_counts: defaultdict[str, set[str]] = defaultdict(set)

    @property
    def name(self) -> str:
        """Detector name used in alerts and configuration."""
        return "LateralMovementDetector"

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

    def ingest(self, packet: ParsedPacket) -> None:
        """Record the peer if both ends of the conversation are internal."""
        if (
            packet.src_ip
            and packet.dst_ip
            and self._is_internal(packet.src_ip)
            and self._is_internal(packet.dst_ip)
        ):
            self._src_dst_counts[packet.src_ip].add(packet.dst_ip)

    def evaluate(self) -> list[DetectionAlert]:
        """Emit an alert per fanning-out host, then clear the window."""
        alerts = []
        for src_ip, destinations in self._src_dst_counts.items():
            if len(destinations) >= self.config.internal_connection_threshold:
                alerts.append(
                    self.emit_alert(
                        severity=Severity.HIGH,
                        tactic=MitreTactic.LATERAL_MOVEMENT,
                        src_ip=src_ip,
                        description=(
                            f"Suspicious Lateral Movement: connected to "
                            f"{len(destinations)} internal hosts."
                        ),
                        evidence={"unique_internal_destinations": len(destinations)}
                    )
                )
        self._src_dst_counts.clear()
        return alerts
