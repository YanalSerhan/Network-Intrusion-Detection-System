"""
ARP spoofing and DNS tunnelling detectors.

Data Setup:  Thresholds from config/detectors.json.
Data Input:  ARP and DNS packets.
Data Output: Alerts for gratuitous-ARP floods and high-entropy DNS traffic.

Beaconing lives in `beaconing.py`; port, exfiltration and lateral-movement
detectors live in `movement.py`. The registry auto-discovers every module in
this package, so splitting them changes nothing at runtime.
"""

from collections import defaultdict
from typing import Any

from pydantic import Field

from network_defender.constants import MitreTactic, Protocol, Severity
from network_defender.detectors.base import BaseDetector
from network_defender.detectors.models import DetectionAlert, DetectorConfig
from network_defender.parser.models import ParsedPacket

from .entropy import shannon_entropy


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


class DnsTunnelingConfig(DetectorConfig):
    time_window_seconds: int = Field(default=60)
    query_count_threshold: int = Field(default=50)
    entropy_threshold: float = Field(default=4.5)

class DnsTunnelingDetector(BaseDetector[DnsTunnelingConfig]):
    def __init__(self, config: DnsTunnelingConfig) -> None:
        super().__init__(config)
        self._src_stats: defaultdict[str, dict[str, Any]] = defaultdict(
            lambda: {"count": 0, "high_entropy": 0}
        )

    @property
    def name(self) -> str:
        return "DnsTunnelingDetector"

    def ingest(self, packet: ParsedPacket) -> None:
        if (
            packet.protocol == Protocol.DNS
            and packet.dns
            and packet.dns.query_name
            and packet.src_ip
        ):
            entropy = shannon_entropy(packet.dns.query_name)
            stats = self._src_stats[packet.src_ip]
            stats["count"] += 1
            if entropy > self.config.entropy_threshold:
                stats["high_entropy"] += 1

    def evaluate(self) -> list[DetectionAlert]:
        alerts = []
        for src_ip, stats in self._src_stats.items():
            mostly_high_entropy = stats["high_entropy"] > (stats["count"] * 0.5)
            if stats["count"] >= self.config.query_count_threshold and mostly_high_entropy:
                alerts.append(
                    self.emit_alert(
                        severity=Severity.HIGH,
                        tactic=MitreTactic.COMMAND_AND_CONTROL,
                        src_ip=src_ip,
                        description=(
                            "Possible DNS Tunneling: high frequency of "
                            "high-entropy DNS queries."
                        ),
                        evidence=stats
                    )
                )
        self._src_stats.clear()
        return alerts
