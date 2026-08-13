"""
Port scan detectors: connect scans and half-open SYN scans.

Data Setup:  A set of destination ports per source, reset every window.
Data Input:  Parsed packets, one at a time.
Data Output: One DetectionAlert per source that touched too many ports.

Both count *unique* ports rather than packets. A client retrying one port is
not scanning however many times it retries, and a scanner touching a thousand
ports once each is — the distinguishing signal is breadth, not volume.

The two overlap on purpose. A half-open scan satisfies both, so a SYN scan
raises two alerts: one saying "this host is scanning" and one saying "and it
is doing so without completing handshakes", which is what tells an analyst the
scanner was trying not to be logged.
"""

from collections import defaultdict

from pydantic import Field

from network_defender.constants import MitreTactic, Protocol, Severity
from network_defender.detectors.base import BaseDetector
from network_defender.detectors.models import DetectionAlert, DetectorConfig
from network_defender.parser.models import ParsedPacket


class TcpPortScanConfig(DetectorConfig):
    """Tunables for the TCP port scan detector."""

    time_window_seconds: int = Field(default=10)
    unique_ports_threshold: int = Field(default=15)


class TcpPortScanDetector(BaseDetector[TcpPortScanConfig]):
    """
    Detects one source reaching for many distinct ports on the network.

    Deliberately flag-agnostic: it sees connect scans, half-open scans and
    anything else that fans out across ports, at the cost of also seeing a
    busy load balancer. The SYN scan detector below is the narrower signal.
    """

    def __init__(self, config: TcpPortScanConfig) -> None:
        """
        Initialise the detector.

        Args:
            config: Validated configuration holding the unique-port threshold.
        """
        super().__init__(config)
        self._state: defaultdict[str, set[int]] = defaultdict(set)

    @property
    def name(self) -> str:
        """Detector name used in alerts and configuration."""
        return "TcpPortScanDetector"

    def ingest(self, packet: ParsedPacket) -> None:
        """Record the destination port this source touched."""
        if packet.protocol == Protocol.TCP and packet.src_ip and packet.dst_port:
            self._state[packet.src_ip].add(packet.dst_port)

    def evaluate(self) -> list[DetectionAlert]:
        """Emit an alert per scanning source, then clear the window."""
        alerts = []
        for src_ip, ports in self._state.items():
            if len(ports) >= self.config.unique_ports_threshold:
                alerts.append(
                    self.emit_alert(
                        severity=Severity.HIGH,
                        tactic=MitreTactic.RECONNAISSANCE,
                        src_ip=src_ip,
                        description=f"TCP Port Scan detected: {len(ports)} unique ports scanned.",
                        evidence={"unique_ports": len(ports)},
                    )
                )
        self._state.clear()
        return alerts


class SynScanConfig(DetectorConfig):
    """Tunables for the SYN scan detector."""

    time_window_seconds: int = Field(default=10)
    unique_ports_threshold: int = Field(default=10)


class SynScanDetector(BaseDetector[SynScanConfig]):
    """
    Detects half-open scanning: SYNs sent without completing the handshake.

    Counts bare SYNs only. A SYN-ACK is a server answering rather than a host
    probing, so including it would report every busy server as a scanner —
    and the whole value of this detector over the broader port scan above is
    that it says the source was avoiding a completed, logged connection.

    Its threshold is lower for the same reason: the signal is more specific,
    so less of it is needed before the finding is worth raising.
    """

    def __init__(self, config: SynScanConfig) -> None:
        """
        Initialise the detector.

        Args:
            config: Validated configuration holding the unique-port threshold.
        """
        super().__init__(config)
        self._state: defaultdict[str, set[int]] = defaultdict(set)

    @property
    def name(self) -> str:
        """Detector name used in alerts and configuration."""
        return "SynScanDetector"

    def ingest(self, packet: ParsedPacket) -> None:
        """Record the port if this is a SYN with no ACK set."""
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
        """Emit an alert per scanning source, then clear the window."""
        alerts = []
        for src_ip, ports in self._state.items():
            if len(ports) >= self.config.unique_ports_threshold:
                alerts.append(
                    self.emit_alert(
                        severity=Severity.HIGH,
                        tactic=MitreTactic.RECONNAISSANCE,
                        src_ip=src_ip,
                        description=f"SYN Scan detected: {len(ports)} unique ports targeted.",
                        evidence={"unique_ports": len(ports)},
                    )
                )
        self._state.clear()
        return alerts
