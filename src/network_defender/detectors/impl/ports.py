"""
Suspicious destination port detector.

Data Setup:  Port list from config/detectors.json.
Data Input:  Parsed packets.
Data Output: One alert per (src, dst, port) triple seen in the window.

Kept apart from the volume-based detectors in `movement`: this one is a pure
signature match on a port list an analyst edits, with no accumulated state to
threshold. It is also the noisiest thing to tune, so it benefits from being
findable on its own.
"""

from pydantic import Field

from network_defender.constants import MitreTactic, Severity
from network_defender.detectors.base import BaseDetector
from network_defender.detectors.models import DetectionAlert, DetectorConfig
from network_defender.parser.models import ParsedPacket


class SuspiciousPortConfig(DetectorConfig):
    """Ports treated as inherently suspicious destinations."""

    suspicious_ports: list[int] = Field(default_factory=lambda: [6667, 31337, 4444, 4445])


class SuspiciousPortDetector(BaseDetector[SuspiciousPortConfig]):
    """Flags connections to ports associated with C2 and backdoor tooling."""

    def __init__(self, config: SuspiciousPortConfig) -> None:
        """
        Initialise the detector.

        Args:
            config: Validated configuration holding the suspicious port list.
        """
        super().__init__(config)
        self._suspicious_ports = set(config.suspicious_ports)
        # A set, not a counter: repeated packets on one connection are one
        # finding, and dedup downstream should not have to undo the noise.
        self._seen: set[tuple[str, str, int]] = set()

    @property
    def name(self) -> str:
        """Detector name used in alerts and configuration."""
        return "SuspiciousPortDetector"

    def ingest(self, packet: ParsedPacket) -> None:
        """Record the connection if its destination port is on the list."""
        if (
            packet.dst_port is not None
            and packet.dst_port in self._suspicious_ports
            and packet.src_ip
            and packet.dst_ip
        ):
            self._seen.add((packet.src_ip, packet.dst_ip, packet.dst_port))

    def evaluate(self) -> list[DetectionAlert]:
        """Emit one alert per distinct connection, then clear the window."""
        alerts = [
            self.emit_alert(
                severity=Severity.MEDIUM,
                tactic=MitreTactic.COMMAND_AND_CONTROL,
                src_ip=src_ip,
                dst_ip=dst_ip,
                description=f"Connection to suspicious port: {port}",
                evidence={"dst_port": port},
            )
            for src_ip, dst_ip, port in self._seen
        ]
        self._seen.clear()
        return alerts
