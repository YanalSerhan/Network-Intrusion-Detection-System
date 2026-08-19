"""
Port scan detectors: connect scans and half-open SYN scans.

Data Setup:  A set of destination ports per source, reset every window.
Data Input:  Parsed packets, one at a time.
Data Output: One DetectionAlert per source that touched too many ports.

Both count *unique* ports rather than packets — see `breadth`, which holds the
shared measurement. A client retrying one port is not scanning however many
times it retries; a scanner touching a thousand ports once each is.

The two overlap on purpose. A half-open scan satisfies both, so a SYN scan
raises two alerts: one saying "this host is scanning" and one saying "and it
is doing so without completing handshakes", which is what tells an analyst the
scanner was trying not to be logged.
"""

from pydantic import Field

from network_defender.constants import MitreTactic, Protocol, Severity
from network_defender.detectors.models import DetectorConfig
from network_defender.parser.models import ParsedPacket

from .breadth import BreadthDetector


class PortBreadthDetector[TConfig: DetectorConfig](BreadthDetector[TConfig]):
    """
    Counts distinct destination ports per source.

    Abstract: it fixes what a port scan measures and leaves the two concrete
    detectors to say which packets qualify and how many are too many. They are
    siblings rather than one subclassing the other — a SYN scan is not a
    special kind of connect scan, they are two readings of the same traffic.
    """

    evidence_key = "unique_ports"
    severity = Severity.HIGH
    tactic = MitreTactic.RECONNAISSANCE

    def counts(self, packet: ParsedPacket) -> bool:
        """Return True for any TCP packet carrying a destination port."""
        return bool(packet.protocol == Protocol.TCP and packet.dst_port)

    def peer(self, packet: ParsedPacket) -> str | None:
        """A port is the unit of breadth for a scan."""
        return str(packet.dst_port)


class TcpPortScanConfig(DetectorConfig):
    """Tunables for the TCP port scan detector."""

    time_window_seconds: int = Field(default=10)
    unique_ports_threshold: int = Field(default=15)


class TcpPortScanDetector(PortBreadthDetector[TcpPortScanConfig]):
    """
    Detects one source reaching for many distinct ports on the network.

    Deliberately flag-agnostic: it sees connect scans, half-open scans and
    anything else that fans out across ports, at the cost of also seeing a
    busy load balancer. The SYN scan detector below is the narrower signal.
    """

    @property
    def name(self) -> str:
        """Detector name used in alerts and configuration."""
        return "TcpPortScanDetector"

    @property
    def threshold(self) -> int:
        """Distinct ports per window at or above which to report a scan."""
        return self.config.unique_ports_threshold

    def describe(self, count: int) -> str:
        """Describe the scan for the analyst reading the alert."""
        return f"TCP Port Scan detected: {count} unique ports scanned."


class SynScanConfig(DetectorConfig):
    """Tunables for the SYN scan detector."""

    time_window_seconds: int = Field(default=10)
    unique_ports_threshold: int = Field(default=10)


class SynScanDetector(PortBreadthDetector[SynScanConfig]):
    """
    Detects half-open scanning: SYNs sent without completing the handshake.

    Counts bare SYNs only. A SYN-ACK is a server answering rather than a host
    probing, so including it would report every busy server as a scanner —
    and the whole value of this detector over the broader port scan above is
    that it says the source was avoiding a completed, logged connection.

    Its threshold is lower for the same reason: the signal is more specific,
    so less of it is needed before the finding is worth raising.
    """

    @property
    def name(self) -> str:
        """Detector name used in alerts and configuration."""
        return "SynScanDetector"

    @property
    def threshold(self) -> int:
        """Distinct ports per window at or above which to report a scan."""
        return self.config.unique_ports_threshold

    def counts(self, packet: ParsedPacket) -> bool:
        """Return True for a SYN with no ACK — a handshake never completed."""
        return bool(
            super().counts(packet)
            and packet.tcp_flags
            and packet.tcp_flags.syn
            and not packet.tcp_flags.ack
        )

    def describe(self, count: int) -> str:
        """Describe the scan for the analyst reading the alert."""
        return f"SYN Scan detected: {count} unique ports targeted."
