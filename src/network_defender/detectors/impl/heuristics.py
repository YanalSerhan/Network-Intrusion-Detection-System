"""
Detectors for various heuristic anomalies.
"""

import math
from collections import defaultdict
from typing import Any

from pydantic import Field

from network_defender.constants import MitreTactic, Protocol, Severity
from network_defender.detectors.base import BaseDetector
from network_defender.detectors.models import DetectionAlert, DetectorConfig
from network_defender.parser.models import ParsedPacket


def shannon_entropy(s: str) -> float:
    """Calculate the Shannon entropy of a string."""
    if not s:
        return 0.0
    freq: defaultdict[str, int] = defaultdict(int)
    for c in s:
        freq[c] += 1
    entropy = 0.0
    for count in freq.values():
        p = count / len(s)
        entropy -= p * math.log2(p)
    return entropy

# 1. ARP Spoofing
class ArpSpoofingConfig(DetectorConfig):
    time_window_seconds: int = Field(default=60)
    gratuitous_arp_threshold: int = Field(default=5)

class ArpSpoofingDetector(BaseDetector[ArpSpoofingConfig]):
    """
    Detects excessive gratuitous ARPs or MAC-IP mapping changes (simplified).
    Currently implemented as counting ARP packets from a single source.
    """
    def __init__(self, config: ArpSpoofingConfig) -> None:
        super().__init__(config)
        self._src_counts: defaultdict[str, int] = defaultdict(int)

    @property
    def name(self) -> str:
        return "ArpSpoofingDetector"

    def ingest(self, packet: ParsedPacket) -> None:
        if packet.protocol == Protocol.ARP and packet.src_ip:
            self._src_counts[packet.src_ip] += 1

    def evaluate(self) -> list[DetectionAlert]:
        alerts = []
        for src_ip, count in self._src_counts.items():
            if count >= self.config.gratuitous_arp_threshold:
                alerts.append(
                    self.emit_alert(
                        severity=Severity.HIGH,
                        tactic=MitreTactic.CREDENTIAL_ACCESS,
                        src_ip=src_ip,
                        description=f"Possible ARP Spoofing detected: {count} ARP packets.",
                        evidence={"arp_count": count}
                    )
                )
        self._src_counts.clear()
        return alerts


# 2. DNS Tunneling
class DnsTunnelingConfig(DetectorConfig):
    time_window_seconds: int = Field(default=60)
    query_count_threshold: int = Field(default=50)
    entropy_threshold: float = Field(default=4.5)

class DnsTunnelingDetector(BaseDetector[DnsTunnelingConfig]):
    def __init__(self, config: DnsTunnelingConfig) -> None:
        super().__init__(config)
        self._src_stats: defaultdict[str, dict[str, Any]] = defaultdict(lambda: {"count": 0, "high_entropy": 0})

    @property
    def name(self) -> str:
        return "DnsTunnelingDetector"

    def ingest(self, packet: ParsedPacket) -> None:
        if packet.protocol == Protocol.DNS and packet.dns and packet.dns.query_name and packet.src_ip:
            entropy = shannon_entropy(packet.dns.query_name)
            stats = self._src_stats[packet.src_ip]
            stats["count"] += 1
            if entropy > self.config.entropy_threshold:
                stats["high_entropy"] += 1

    def evaluate(self) -> list[DetectionAlert]:
        alerts = []
        for src_ip, stats in self._src_stats.items():
            if stats["count"] >= self.config.query_count_threshold and stats["high_entropy"] > (stats["count"] * 0.5):
                alerts.append(
                    self.emit_alert(
                        severity=Severity.HIGH,
                        tactic=MitreTactic.COMMAND_AND_CONTROL,
                        src_ip=src_ip,
                        description="Possible DNS Tunneling: high frequency of high-entropy DNS queries.",
                        evidence=stats
                    )
                )
        self._src_stats.clear()
        return alerts


# 3. Beaconing
class BeaconingConfig(DetectorConfig):
    time_window_seconds: int = Field(default=3600)
    connection_count_threshold: int = Field(default=10)
    interval_variance_tolerance: float = Field(default=0.1)

class BeaconingDetector(BaseDetector[BeaconingConfig]):
    def __init__(self, config: BeaconingConfig) -> None:
        super().__init__(config)
        self._src_dst_timestamps: defaultdict[tuple[str, str], list[float]] = defaultdict(list)

    @property
    def name(self) -> str:
        return "BeaconingDetector"

    def ingest(self, packet: ParsedPacket) -> None:
        if packet.protocol in [Protocol.TCP, Protocol.HTTP, Protocol.TLS] and packet.src_ip and packet.dst_ip:
            self._src_dst_timestamps[(packet.src_ip, packet.dst_ip)].append(packet.timestamp.timestamp())

    def evaluate(self) -> list[DetectionAlert]:
        alerts = []
        for (src_ip, dst_ip), timestamps in self._src_dst_timestamps.items():
            if len(timestamps) >= self.config.connection_count_threshold:
                intervals = [timestamps[i] - timestamps[i-1] for i in range(1, len(timestamps))]
                if len(intervals) > 0:
                    mean_interval = sum(intervals) / len(intervals)
                    if mean_interval > 0:
                        variance = sum((x - mean_interval)**2 for x in intervals) / len(intervals)
                        std_dev = math.sqrt(variance)
                        
                        if (std_dev / mean_interval) <= self.config.interval_variance_tolerance:
                            alerts.append(
                                self.emit_alert(
                                    severity=Severity.HIGH,
                                    tactic=MitreTactic.COMMAND_AND_CONTROL,
                                    src_ip=src_ip,
                                    dst_ip=dst_ip,
                                    description="Possible Beaconing detected: regular connections to same destination.",
                                    evidence={"mean_interval": mean_interval, "connection_count": len(timestamps)}
                                )
                            )
        self._src_dst_timestamps.clear()
        return alerts


# 4. Suspicious Port
class SuspiciousPortConfig(DetectorConfig):
    suspicious_ports: list[int] = Field(default_factory=lambda: [6667, 31337, 4444, 4445])

class SuspiciousPortDetector(BaseDetector[SuspiciousPortConfig]):
    def __init__(self, config: SuspiciousPortConfig) -> None:
        super().__init__(config)
        self._suspicious_ports = set(config.suspicious_ports)
        self._seen: set[tuple[str, str, int]] = set()

    @property
    def name(self) -> str:
        return "SuspiciousPortDetector"

    def ingest(self, packet: ParsedPacket) -> None:
        if packet.dst_port is not None and packet.dst_port in self._suspicious_ports and packet.src_ip and packet.dst_ip:
            self._seen.add((packet.src_ip, packet.dst_ip, packet.dst_port))

    def evaluate(self) -> list[DetectionAlert]:
        alerts = []
        for src_ip, dst_ip, port in self._seen:
            alerts.append(
                self.emit_alert(
                    severity=Severity.MEDIUM,
                    tactic=MitreTactic.COMMAND_AND_CONTROL,
                    src_ip=src_ip,
                    dst_ip=dst_ip,
                    description=f"Connection to suspicious port: {port}",
                    evidence={"dst_port": port}
                )
            )
        self._seen.clear()
        return alerts


# 5. Data Exfiltration
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


# 6. Lateral Movement
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
        return ip.startswith("10.") or ip.startswith("192.168.") or (ip.startswith("172.") and 16 <= int(ip.split(".")[1]) <= 31)

    def ingest(self, packet: ParsedPacket) -> None:
        if packet.src_ip and packet.dst_ip and self._is_internal(packet.src_ip) and self._is_internal(packet.dst_ip):
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
                        description=f"Suspicious Lateral Movement: connected to {len(destinations)} internal hosts.",
                        evidence={"unique_internal_destinations": len(destinations)}
                    )
                )
        self._src_dst_counts.clear()
        return alerts
