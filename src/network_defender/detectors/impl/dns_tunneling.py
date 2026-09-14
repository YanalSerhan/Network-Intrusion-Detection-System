"""
The DNS tunnelling detector.

Data Setup:  Thresholds and the domain allowlist from config/detectors.json.
Data Input:  DNS query packets.
Data Output: Alerts for sources resolving mostly high-entropy names, in volume.

Split out of `heuristics` when the allowlist landed: the two detectors that
shared that file had nothing in common but the file, and one of them had
grown past what a reader can hold.
"""

from pydantic import Field

from network_defender.constants import MitreTactic, Protocol, Severity
from network_defender.detectors.base import BaseDetector
from network_defender.detectors.domains import is_allowlisted
from network_defender.detectors.models import DetectionAlert, DetectorConfig
from network_defender.detectors.window_counts import SlidingCounter
from network_defender.parser.models import ParsedPacket

from .entropy import shannon_entropy


class DnsTunnelingConfig(DetectorConfig):
    """Tunables for the DNS tunnelling detector."""

    time_window_seconds: int = Field(default=60)
    query_count_threshold: int = Field(default=50)
    entropy_threshold: float = Field(default=4.5)
    allowed_domains: list[str] = Field(
        default_factory=list,
        description=(
            "Registered domains whose queries are not counted. Ships empty on "
            "purpose: the names worth trusting are the ones a given site's own "
            "endpoint agents use, and a default list would be a guess about "
            "someone else's estate."
        ),
    )

class DnsTunnelingDetector(BaseDetector[DnsTunnelingConfig]):
    """
    Detects DNS queries carrying encoded payload rather than hostnames.

    Two signals together, because neither alone is enough: query volume, and
    what fraction of those queries have high-entropy names. A real hostname is
    a word or two and scores low on Shannon entropy; base32-encoded tunnel
    payload is close to uniform over its alphabet and scores high. Volume
    alone would flag a busy resolver, and entropy alone would flag the random
    subdomains that CDNs and malware sandboxes generate legitimately.

    Neither signal separates a tunnel from an endpoint agent doing encoded
    reputation lookups, which is a real product behaviour and byte for byte
    the same shape. `allowed_domains` is the third signal, and it is the
    operator's rather than the detector's: one entry for the vendor's
    registered domain excludes its queries and nothing else's. Matching is on
    the registered domain because a tunnel's whole technique is that every
    query name is different.
    """

    #: A source must have more high-entropy queries than ordinary ones before
    #: the finding is raised. Volume alone flags a busy resolver.
    MAJORITY = 0.5

    def __init__(self, config: DnsTunnelingConfig) -> None:
        """Initialise with the validated query-count and entropy thresholds."""
        super().__init__(config)
        # Two counters over one window rather than one counter of pairs: they
        # advance on the same packets, so their clocks stay in step, and the
        # ratio is read from the same instant in both.
        self._queries = SlidingCounter(self.window_seconds)
        self._encoded = SlidingCounter(self.window_seconds)

    @property
    def name(self) -> str:
        """Detector name used in alerts and configuration."""
        return "DnsTunnelingDetector"

    def ingest(self, packet: ParsedPacket) -> None:
        """Tally the query against its source, and whether it looks encoded."""
        if not (
            packet.protocol == Protocol.DNS
            and packet.dns
            and packet.dns.query_name
            and packet.src_ip
        ):
            return
        if is_allowlisted(packet.dns.query_name, self.config.allowed_domains):
            # Not counted at all, rather than counted and excused: an allowed
            # domain must not dilute the high-entropy majority either way.
            return
        at = packet.timestamp.timestamp()
        self._queries.record(packet.src_ip, at)
        if shannon_entropy(packet.dns.query_name) > self.config.entropy_threshold:
            self._encoded.record(packet.src_ip, at)

    def evaluate(self) -> list[DetectionAlert]:
        """Report each source newly resolving mostly encoded names, in volume."""
        alerts = []
        live: set[str] = set()
        for src_ip, count in self._queries.totals():
            live.add(src_ip)
            encoded = self._encoded.total(src_ip)
            tunnelling = (
                count >= self.config.query_count_threshold and encoded > count * self.MAJORITY
            )
            if not self.report_once(src_ip, tunnelling):
                continue
            alerts.append(
                self.emit_alert(
                    severity=Severity.HIGH,
                    tactic=MitreTactic.COMMAND_AND_CONTROL,
                    src_ip=src_ip,
                    description=(
                        "Possible DNS Tunneling: high frequency of high-entropy DNS queries."
                    ),
                    evidence={"count": count, "high_entropy": encoded},
                )
            )
        self.forget_absent(live)
        return alerts
