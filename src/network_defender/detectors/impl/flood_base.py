"""
The shape every volumetric flood detector shares.

Data Setup:  A per-destination counter, reset every evaluation window.
Data Input:  Parsed packets, one at a time.
Data Output: One DetectionAlert per destination that crossed its threshold.

All three flood detectors do the same thing: decide whether a packet counts,
add one to a per-destination tally, and alert on the tallies that cross a
threshold. Writing that out three times meant three chances to fix a bug in
one place and miss the other two — and the mutation spot check found exactly
that class of drift in the comparison operators.

Counting toward the *destination* rather than the source is the important
decision here. A flood is usually distributed, which is the point of it, so
counting per source splits one attack across thousands of counters that never
individually reach a threshold. The victim is the one thing every packet of a
flood has in common.
"""

from abc import abstractmethod
from collections import defaultdict

from network_defender.constants import MitreTactic, Severity
from network_defender.detectors.base import BaseDetector
from network_defender.detectors.models import DetectionAlert, DetectorConfig
from network_defender.parser.models import ParsedPacket


class DestinationFloodDetector[TConfig: DetectorConfig](BaseDetector[TConfig]):
    """
    Counts qualifying packets per destination and alerts past a threshold.

    Subclasses supply three things: which packets count, how many are too
    many, and how bad it is when they are. Everything else — the tally, the
    alert, clearing the window — is the same for all of them.
    """

    #: Evidence key the alert reports the tally under. Named per subclass
    #: because confidence scoring looks the magnitude up by this key.
    evidence_key: str = "packet_count"

    #: Severity of the resulting alert, which differs by how much damage the
    #: flood does at the same packet rate.
    severity: Severity = Severity.HIGH

    def __init__(self, config: TConfig) -> None:
        """
        Initialise with a validated configuration.

        Args:
            config: The subclass's configuration, already validated.
        """
        super().__init__(config)
        self._counts: defaultdict[str, int] = defaultdict(int)

    @abstractmethod
    def counts(self, packet: ParsedPacket) -> bool:
        """
        Return True if this packet is part of the flood being watched for.

        Args:
            packet: The packet to classify.

        Returns:
            Whether it should be added to its destination's tally.
        """

    @property
    @abstractmethod
    def threshold(self) -> int:
        """Packets per window at or above which the flood is reported."""

    @abstractmethod
    def describe(self, count: int) -> str:
        """
        Return the alert description for a tally.

        Args:
            count: Packets counted against one destination.

        Returns:
            The human-readable description an analyst reads first.
        """

    def ingest(self, packet: ParsedPacket) -> None:
        """Add the packet to its destination's tally if it qualifies."""
        if packet.dst_ip and self.counts(packet):
            self._counts[packet.dst_ip] += 1

    def evaluate(self) -> list[DetectionAlert]:
        """Emit one alert per flooded destination, then clear the window."""
        alerts = [
            self.emit_alert(
                severity=self.severity,
                tactic=MitreTactic.IMPACT,
                dst_ip=dst_ip,
                description=self.describe(count),
                evidence={self.evidence_key: count},
            )
            for dst_ip, count in self._counts.items()
            if count >= self.threshold
        ]
        self._counts.clear()
        return alerts
