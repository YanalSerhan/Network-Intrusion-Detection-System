"""
Detectors for port scanning activity.
"""

from collections import defaultdict

from pydantic import Field

from network_defender.constants import MitreTactic, Protocol, Severity
from network_defender.detectors.base import BaseDetector
from network_defender.detectors.models import DetectionAlert, DetectorConfig
from network_defender.parser.models import ParsedPacket


class TcpPortScanConfig(DetectorConfig):
    time_window_seconds: int = Field(default=10)
    unique_ports_threshold: int = Field(default=15)


class TcpPortScanDetector(BaseDetector[TcpPortScanConfig]):
    """
    Detects a source IP attempting to connect to many unique ports.
    """

    def __init__(self, config: TcpPortScanConfig) -> None:
        super().__init__(config)
        self._state: defaultdict[str, set[int]] = defaultdict(set)

    @property
    def name(self) -> str:
        return "TcpPortScanDetector"

    def ingest(self, packet: ParsedPacket) -> None:
        if packet.protocol == Protocol.TCP and packet.src_ip and packet.dst_port:
            self._state[packet.src_ip].add(packet.dst_port)

    def evaluate(self) -> list[DetectionAlert]:
        alerts = []
        for src_ip, ports in self._state.items():
            if len(ports) >= self.config.unique_ports_threshold:
                alerts.append(
                    self.emit_alert(
                        severity=Severity.HIGH,
                        tactic=MitreTactic.RECONNAISSANCE,
                        src_ip=src_ip,
                        description=f"TCP Port Scan detected: {len(ports)} unique ports scanned.",
                        evidence={"unique_ports": len(ports)}
                    )
                )
        self._state.clear()
        return alerts


class SynScanConfig(DetectorConfig):
    time_window_seconds: int = Field(default=10)
    unique_ports_threshold: int = Field(default=10)


class SynScanDetector(BaseDetector[SynScanConfig]):
    """
    Detects SYN scans (half-open scanning) where an IP sends SYN packets to many unique ports.
    """

    def __init__(self, config: SynScanConfig) -> None:
        super().__init__(config)
        self._state: defaultdict[str, set[int]] = defaultdict(set)

    @property
    def name(self) -> str:
        return "SynScanDetector"

    def ingest(self, packet: ParsedPacket) -> None:
        if (
            packet.protocol == Protocol.TCP 
            and packet.tcp_flags 
            and packet.tcp_flags.syn 
            and not packet.tcp_flags.ack 
            and packet.src_ip 
            and packet.dst_port
        ):
            self._state[packet.src_ip].add(packet.dst_port)

    def evaluate(self) -> list[DetectionAlert]:
        alerts = []
        for src_ip, ports in self._state.items():
            if len(ports) >= self.config.unique_ports_threshold:
                alerts.append(
                    self.emit_alert(
                        severity=Severity.HIGH,
                        tactic=MitreTactic.RECONNAISSANCE,
                        src_ip=src_ip,
                        description=f"SYN Scan detected: {len(ports)} unique ports targeted.",
                        evidence={"unique_ports": len(ports)}
                    )
                )
        self._state.clear()
        return alerts
