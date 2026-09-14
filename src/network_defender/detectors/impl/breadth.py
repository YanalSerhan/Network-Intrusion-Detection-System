"""
The shape shared by detectors that measure breadth rather than volume.

Data Setup:  A set of distinct peers per source, reset every window.
Data Input:  Parsed packets, one at a time.
Data Output: One DetectionAlert per source that reached too many peers.

`CountingDetector` next door tallies how *many* packets a source sent. These
three ask a different question: how many *distinct* things did it touch? A
client retrying one port is not scanning however many times it retries, and a
host that talks to one file server all day is not moving laterally however
much traffic it sends. Deduplicating is the measurement.

Splitting the two rather than parameterising one base keeps each readable:
the state here is a set, the state there is an integer, and the difference
between them is the whole point of having two detectors.
"""

from abc import abstractmethod

from network_defender.constants import MitreTactic, Severity
from network_defender.detectors.base import BaseDetector
from network_defender.detectors.models import DetectionAlert, DetectorConfig
from network_defender.detectors.window_peers import SlidingPeers
from network_defender.parser.models import ParsedPacket


class BreadthDetector[TConfig: DetectorConfig](BaseDetector[TConfig]):
    """
    Counts distinct peers per source and alerts past a threshold.

    Subclasses supply which packets count, what a "peer" is for them, how many
    are too many, and what to say. The peer set, the window it expires on, and
    the alert are shared.
    """

    #: Evidence key the alert reports the count under. Confidence scoring
    #: looks the magnitude up by this key, so it must match the entry in
    #: `services/alerts/reference_thresholds.py`.
    evidence_key: str = "unique_peers"

    #: Severity of the resulting alert.
    severity: Severity = Severity.HIGH

    #: MITRE tactic the finding is attributed to.
    tactic: MitreTactic = MitreTactic.RECONNAISSANCE

    def __init__(self, config: TConfig) -> None:
        """
        Initialise with a validated configuration.

        Args:
            config: The subclass's configuration, already validated.
        """
        super().__init__(config)
        self._peers = SlidingPeers(self.window_seconds)

    @abstractmethod
    def counts(self, packet: ParsedPacket) -> bool:
        """
        Return True if this packet is part of what is being watched for.

        Args:
            packet: The packet to classify.

        Returns:
            Whether its peer should be recorded against its source.
        """

    @abstractmethod
    def peer(self, packet: ParsedPacket) -> str | None:
        """
        Return the thing whose distinctness is being counted.

        A destination port for a scan, a destination host for lateral
        movement — whatever the detector considers one unit of breadth.

        Args:
            packet: A packet that has already passed `counts`.

        Returns:
            The peer identifier, or None to ignore the packet.
        """

    @property
    @abstractmethod
    def threshold(self) -> int:
        """Distinct peers per window at or above which to report."""

    @abstractmethod
    def describe(self, count: int) -> str:
        """
        Return the alert description for a peer count.

        Args:
            count: Distinct peers reached by one source.

        Returns:
            The human-readable description an analyst reads first.
        """

    def ingest(self, packet: ParsedPacket) -> None:
        """Record the packet's peer against its source if it qualifies."""
        if not (packet.src_ip and self.counts(packet)):
            return
        peer = self.peer(packet)
        if peer is not None:
            self._peers.record(packet.src_ip, peer, packet.timestamp.timestamp())

    def evaluate(self) -> list[DetectionAlert]:
        """Report each source that has newly crossed its threshold."""
        alerts = []
        live: set[str] = set()
        for src_ip, count in self._peers.counts():
            live.add(src_ip)
            if self.report_once(src_ip, count >= self.threshold):
                alerts.append(
                    self.emit_alert(
                        severity=self.severity,
                        tactic=self.tactic,
                        src_ip=src_ip,
                        description=self.describe(count),
                        evidence={self.evidence_key: count},
                    )
                )
        self.forget_absent(live)
        return alerts
