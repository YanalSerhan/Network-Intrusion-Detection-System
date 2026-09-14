"""
Suspicious destination port detector.

Data Setup:  Port list from config/detectors.json.
Data Input:  Parsed packets.
Data Output: One alert per (src, dst, port) triple seen in the window.

Kept apart from the volume-based detectors in `movement`: this one is a pure
signature match on a port list an analyst edits, with no accumulated state to
threshold. It is also the noisiest thing to tune, so it benefits from being
findable on its own.
"""

from pydantic import Field

from network_defender.constants import MitreTactic, Severity
from network_defender.detectors.base import BaseDetector
from network_defender.detectors.models import DetectionAlert, DetectorConfig
from network_defender.detectors.window_peers import SlidingPeers
from network_defender.parser.models import ParsedPacket

#: Joins a destination and port into one peer identifier. Neither part can
#: contain it, so the pair is recoverable without a second mapping.
ENDPOINT = "|"


class SuspiciousPortConfig(DetectorConfig):
    """Ports treated as inherently suspicious destinations."""

    suspicious_ports: list[int] = Field(default_factory=lambda: [6667, 31337, 4444, 4445])


class SuspiciousPortDetector(BaseDetector[SuspiciousPortConfig]):
    """Flags connections to ports associated with C2 and backdoor tooling."""

    def __init__(self, config: SuspiciousPortConfig) -> None:
        """
        Initialise the detector.

        Args:
            config: Validated configuration holding the suspicious port list.
        """
        super().__init__(config)
        self._suspicious_ports = set(config.suspicious_ports)
        # Distinct endpoints, not a count: repeated packets on one connection
        # are one finding, and dedup downstream should not have to undo the
        # noise. They expire like every other window, so a connection made an
        # hour ago stops being reported as current.
        self._seen = SlidingPeers(self.window_seconds)

    @property
    def name(self) -> str:
        """Detector name used in alerts and configuration."""
        return "SuspiciousPortDetector"

    def ingest(self, packet: ParsedPacket) -> None:
        """Record the connection if its destination port is on the list."""
        if (
            packet.dst_port is not None
            and packet.dst_port in self._suspicious_ports
            and packet.src_ip
            and packet.dst_ip
        ):
            self._seen.record(
                packet.src_ip,
                f"{packet.dst_ip}{ENDPOINT}{packet.dst_port}",
                packet.timestamp.timestamp(),
            )

    def evaluate(self) -> list[DetectionAlert]:
        """Report each connection to a flagged port, once."""
        alerts = []
        live: set[str] = set()
        for src_ip, endpoints in self._seen.entries():
            for endpoint in endpoints:
                key = f"{src_ip}{ENDPOINT}{endpoint}"
                live.add(key)
                if not self.report_once(key, over_threshold=True):
                    continue
                dst_ip, port = endpoint.split(ENDPOINT, 1)
                alerts.append(
                    self.emit_alert(
                        severity=Severity.MEDIUM,
                        tactic=MitreTactic.COMMAND_AND_CONTROL,
                        src_ip=src_ip,
                        dst_ip=dst_ip,
                        description=f"Connection to suspicious port: {port}",
                        evidence={"dst_port": int(port)},
                    )
                )
        self.forget_absent(live)
        return alerts
