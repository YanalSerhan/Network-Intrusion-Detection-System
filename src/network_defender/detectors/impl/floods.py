"""
Detectors for flood attacks (DoS/DDoS).
"""

from collections import defaultdict

from pydantic import Field

from network_defender.constants import MitreTactic, Protocol, Severity
from network_defender.detectors.base import BaseDetector
from network_defender.detectors.models import DetectionAlert, DetectorConfig
from network_defender.parser.models import ParsedPacket


class SynFloodConfig(DetectorConfig):
    time_window_seconds: int = Field(default=1)
    syn_count_threshold: int = Field(default=100)


class SynFloodDetector(BaseDetector[SynFloodConfig]):
    """
    Detects a high volume of SYN packets from a single source or to a single destination.
    """

    def __init__(self, config: SynFloodConfig) -> None:
        super().__init__(config)
        self._dst_syn_counts: defaultdict[str, int] = defaultdict(int)

    @property
    def name(self) -> str:
        return "SynFloodDetector"

    def ingest(self, packet: ParsedPacket) -> None:
        if (
            packet.protocol == Protocol.TCP 
            and packet.tcp_flags 
            and packet.tcp_flags.syn 
            and packet.dst_ip
        ):
            self._dst_syn_counts[packet.dst_ip] += 1

    def evaluate(self) -> list[DetectionAlert]:
        alerts = []
        for dst_ip, count in self._dst_syn_counts.items():
            if count >= self.config.syn_count_threshold:
                alerts.append(
                    self.emit_alert(
                        severity=Severity.CRITICAL,
                        tactic=MitreTactic.IMPACT,
                        dst_ip=dst_ip,
                        description=f"SYN Flood detected: {count} SYN packets to destination.",
                        evidence={"syn_count": count}
                    )
                )
        self._dst_syn_counts.clear()
        return alerts


class UdpFloodConfig(DetectorConfig):
    time_window_seconds: int = Field(default=1)
    udp_count_threshold: int = Field(default=200)


class UdpFloodDetector(BaseDetector[UdpFloodConfig]):
    """
    Detects a high volume of UDP packets to a single destination.
    """

    def __init__(self, config: UdpFloodConfig) -> None:
        super().__init__(config)
        self._dst_udp_counts: defaultdict[str, int] = defaultdict(int)

    @property
    def name(self) -> str:
        return "UdpFloodDetector"

    def ingest(self, packet: ParsedPacket) -> None:
        if packet.protocol == Protocol.UDP and packet.dst_ip:
            self._dst_udp_counts[packet.dst_ip] += 1

    def evaluate(self) -> list[DetectionAlert]:
        alerts = []
        for dst_ip, count in self._dst_udp_counts.items():
            if count >= self.config.udp_count_threshold:
                alerts.append(
                    self.emit_alert(
                        severity=Severity.HIGH,
                        tactic=MitreTactic.IMPACT,
                        dst_ip=dst_ip,
                        description=f"UDP Flood detected: {count} packets.",
                        evidence={"udp_count": count}
                    )
                )
        self._dst_udp_counts.clear()
        return alerts


class IcmpFloodConfig(DetectorConfig):
    time_window_seconds: int = Field(default=1)
    icmp_count_threshold: int = Field(default=50)


class IcmpFloodDetector(BaseDetector[IcmpFloodConfig]):
    """
    Detects a high volume of ICMP packets (e.g., ping flood) to a destination.
    """

    def __init__(self, config: IcmpFloodConfig) -> None:
        super().__init__(config)
        self._dst_icmp_counts: defaultdict[str, int] = defaultdict(int)

    @property
    def name(self) -> str:
        return "IcmpFloodDetector"

    def ingest(self, packet: ParsedPacket) -> None:
        if packet.protocol == Protocol.ICMP and packet.dst_ip:
            self._dst_icmp_counts[packet.dst_ip] += 1

    def evaluate(self) -> list[DetectionAlert]:
        alerts = []
        for dst_ip, count in self._dst_icmp_counts.items():
            if count >= self.config.icmp_count_threshold:
                alerts.append(
                    self.emit_alert(
                        severity=Severity.MEDIUM,
                        tactic=MitreTactic.IMPACT,
                        dst_ip=dst_ip,
                        description=f"ICMP Flood detected: {count} packets.",
                        evidence={"icmp_count": count}
                    )
                )
        self._dst_icmp_counts.clear()
        return alerts
