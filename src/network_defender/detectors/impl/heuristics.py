"""
The ARP spoofing detector.

Data Setup:  Thresholds from config/detectors.json.
Data Input:  ARP packets.
Data Output: Alerts for gratuitous-ARP floods.

The registry auto-discovers every module in this package, so which detector
lives in which file is an organisational choice with no runtime meaning — and
a file-by-file inventory here would go stale on the next split, as this one
already has twice.
"""

from pydantic import Field

from network_defender.constants import MitreTactic, Protocol, Severity
from network_defender.detectors.impl.counting_endpoints import SourceCountingDetector
from network_defender.detectors.models import DetectorConfig
from network_defender.parser.models import ParsedPacket


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
