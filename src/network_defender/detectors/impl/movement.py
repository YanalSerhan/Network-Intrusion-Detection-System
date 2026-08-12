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
    time_window_seconds: int = Field(default=60)
    bytes_out_threshold: int = Field(default=50_000_000)

class DataExfiltrationDetector(BaseDetector[DataExfiltrationConfig]):
    def __init__(self, config: DataExfiltrationConfig) -> None:
        super().__init__(config)
        self._src_bytes: defaultdict[str, int] = defaultdict(int)

    @property
    def name(self) -> str:
        return "DataExfiltrationDetector"

    def ingest(self, packet: ParsedPacket) -> None:
        if packet.src_ip:
            self._src_bytes[packet.src_ip] += packet.length

    def evaluate(self) -> list[DetectionAlert]:
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
    time_window_seconds: int = Field(default=60)
    internal_connection_threshold: int = Field(default=20)

class LateralMovementDetector(BaseDetector[LateralMovementConfig]):
    def __init__(self, config: LateralMovementConfig) -> None:
        super().__init__(config)
        self._src_dst_counts: defaultdict[str, set[str]] = defaultdict(set)

    @property
    def name(self) -> str:
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
        if (
            packet.src_ip
            and packet.dst_ip
            and self._is_internal(packet.src_ip)
            and self._is_internal(packet.dst_ip)
        ):
            self._src_dst_counts[packet.src_ip].add(packet.dst_ip)

    def evaluate(self) -> list[DetectionAlert]:
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
