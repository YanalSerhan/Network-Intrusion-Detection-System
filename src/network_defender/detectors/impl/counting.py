"""
The shape every threshold-counting detector shares.

Data Setup:  A per-endpoint counter, reset every evaluation window.
Data Input:  Parsed packets, one at a time.
Data Output: One DetectionAlert per endpoint that crossed its threshold.

Six detectors were doing the same four things: decide whether a packet counts,
add one to a tally keyed by an address, alert on the tallies that cross a
threshold, and clear the window. Written out six times it was six chances to
fix a bug in one and miss five — and the mutation spot check found exactly
that, with `>=` weakened to `>` surviving in most of them.

Which endpoint the tally is keyed on is the one real difference, and it is a
decision worth being explicit about:

  * Floods key on the **destination**. A flood is usually distributed, which is
    the point of it, so per-source counters never individually reach a
    threshold while the victim is what every packet has in common.
  * Credential guessing and ARP abuse key on the **source**. One host is doing
    the work, and the attacker is the identity an analyst needs named.
"""

from abc import abstractmethod
from collections import defaultdict

from network_defender.constants import MitreTactic, Severity
from network_defender.detectors.base import BaseDetector
from network_defender.detectors.models import DetectionAlert, DetectorConfig
from network_defender.parser.models import ParsedPacket


class CountingDetector[TConfig: DetectorConfig](BaseDetector[TConfig]):
    """
    Counts qualifying packets per endpoint and alerts past a threshold.

    Subclasses supply what varies: which packets count, which endpoint to
    blame, how many are too many, how bad it is, and what to say. Everything
    else — the tally, the alert, clearing the window — is shared.
    """

    #: Evidence key the alert reports the tally under. Confidence scoring
    #: looks the magnitude up by this key, so it must match the entry in
    #: `services/alerts/reference_thresholds.py`.
    evidence_key: str = "packet_count"

    #: Severity of the resulting alert.
    severity: Severity = Severity.HIGH

    #: MITRE tactic the finding is attributed to.
    tactic: MitreTactic = MitreTactic.IMPACT

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
        Return True if this packet is part of what is being watched for.

        Args:
            packet: The packet to classify.

        Returns:
            Whether it should be added to its endpoint's tally.
        """

    @abstractmethod
    def endpoint(self, packet: ParsedPacket) -> str | None:
        """
        Return the address this packet counts against.

        Args:
            packet: A packet that has already passed `counts`.

        Returns:
            The address to blame, or None to ignore the packet.
        """

    @property
    @abstractmethod
    def threshold(self) -> int:
        """Count per window at or above which the finding is reported."""

    @abstractmethod
    def describe(self, count: int) -> str:
        """
        Return the alert description for a tally.

        Args:
            count: Packets counted against one endpoint.

        Returns:
            The human-readable description an analyst reads first.
        """

    @abstractmethod
    def attribute(self, address: str) -> dict[str, str]:
        """
        Return the alert's address fields for the blamed endpoint.

        Args:
            address: The endpoint that crossed the threshold.

        Returns:
            Keyword arguments naming it as source or destination.
        """

    def ingest(self, packet: ParsedPacket) -> None:
        """Add the packet to its endpoint's tally if it qualifies."""
        if not self.counts(packet):
            return
        address = self.endpoint(packet)
        if address:
            self._counts[address] += 1

    def evaluate(self) -> list[DetectionAlert]:
        """Emit one alert per endpoint over threshold, then clear the window."""
        alerts = [
            self.emit_alert(
                severity=self.severity,
                tactic=self.tactic,
                description=self.describe(count),
                evidence={self.evidence_key: count},
                **self.attribute(address),
            )
            for address, count in self._counts.items()
            if count >= self.threshold
        ]
        self._counts.clear()
        return alerts
