"""
ARP spoofing and DNS tunnelling detectors.

Data Setup:  Thresholds from config/detectors.json.
Data Input:  ARP and DNS packets.
Data Output: Alerts for gratuitous-ARP floods and high-entropy DNS traffic.

The registry auto-discovers every module in this package, so which detector
lives in which file is an organisational choice with no runtime meaning — and
a file-by-file inventory here would go stale on the next split, as this one
already had.
"""

from collections import defaultdict
from typing import Any

from pydantic import Field

from network_defender.constants import MitreTactic, Protocol, Severity
from network_defender.detectors.base import BaseDetector
from network_defender.detectors.models import DetectionAlert, DetectorConfig
from network_defender.parser.models import ParsedPacket

from .counting_endpoints import SourceCountingDetector
from .entropy import shannon_entropy


class ArpSpoofingConfig(DetectorConfig):
    """Tunables for the ARP spoofing detector."""

    time_window_seconds: int = Field(default=60)
    gratuitous_arp_threshold: int = Field(default=5)

class ArpSpoofingDetector(SourceCountingDetector[ArpSpoofingConfig]):
    """
    Detects a host announcing itself over ARP far more often than it should.

    A simplification of full MAC-to-IP mapping surveillance: it counts ARP
    traffic per claimed source rather than tracking which MAC currently owns
    which address. That catches the flood of gratuitous replies a poisoner
    sends to keep its mapping cached, which is the noisy part of the attack,
    and misses a single well-timed reply — which is the quiet part.
    """

    evidence_key = "arp_count"
    severity = Severity.HIGH
    tactic = MitreTactic.CREDENTIAL_ACCESS

    @property
    def name(self) -> str:
        """Detector name used in alerts and configuration."""
        return "ArpSpoofingDetector"

    @property
    def threshold(self) -> int:
        """ARP packets per window at or above which to alert."""
        return self.config.gratuitous_arp_threshold

    def counts(self, packet: ParsedPacket) -> bool:
        """Return True for any ARP packet."""
        return bool(packet.protocol == Protocol.ARP)

    def describe(self, count: int) -> str:
        """Describe the ARP burst for the analyst reading the alert."""
        return f"Possible ARP Spoofing detected: {count} ARP packets."


class DnsTunnelingConfig(DetectorConfig):
    """Tunables for the DNS tunnelling detector."""

    time_window_seconds: int = Field(default=60)
    query_count_threshold: int = Field(default=50)
    entropy_threshold: float = Field(default=4.5)

class DnsTunnelingDetector(BaseDetector[DnsTunnelingConfig]):
    """
    Detects DNS queries carrying encoded payload rather than hostnames.

    Two signals together, because neither alone is enough: query volume, and
    what fraction of those queries have high-entropy names. A real hostname is
    a word or two and scores low on Shannon entropy; base32-encoded tunnel
    payload is close to uniform over its alphabet and scores high. Volume
    alone would flag a busy resolver, and entropy alone would flag the random
    subdomains that CDNs and malware sandboxes generate legitimately.
    """

    def __init__(self, config: DnsTunnelingConfig) -> None:
        """Initialise with the validated query-count and entropy thresholds."""
        super().__init__(config)
        self._src_stats: defaultdict[str, dict[str, Any]] = defaultdict(
            lambda: {"count": 0, "high_entropy": 0}
        )

    @property
    def name(self) -> str:
        """Detector name used in alerts and configuration."""
        return "DnsTunnelingDetector"

    def ingest(self, packet: ParsedPacket) -> None:
        """Tally the query against its source, and whether it looks encoded."""
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
        """Emit an alert per tunnelling source, then clear the window."""
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
