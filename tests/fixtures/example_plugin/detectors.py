"""
A detector written the way docs/EXTENDING.md says to write one.

Imports come from `network_defender.plugins` and the documented modules beside
it, which is the property under test: a plugin that reaches into an internal
module works until the internal module moves, and this file is the check that
the documented surface is enough on its own.

It also follows the guidance rather than only the contract — a sliding counter
over capture time, and `report_once` so an episode is one alert — because
EXTENDING.md points here as the example, and an example that does the thing
the prose warns against is worse than no example.
"""

from network_defender.constants import MitreTactic, Severity
from network_defender.detectors.window_counts import SlidingCounter
from network_defender.parser.models import ParsedPacket
from network_defender.plugins import BaseDetector, DetectionAlert, DetectorConfig


class JumboFrameConfig(DetectorConfig):
    """Tunables for the example detector."""

    time_window_seconds: int = 60
    jumbo_bytes: int = 1500
    jumbo_count_threshold: int = 3


class JumboFrameDetector(BaseDetector[JumboFrameConfig]):
    """Counts oversized frames per source, as an example of the contract."""

    def __init__(self, config: JumboFrameConfig) -> None:
        """Initialise with the validated configuration."""
        super().__init__(config)
        self._counts = SlidingCounter(self.window_seconds)

    @property
    def name(self) -> str:
        """Detector name used in alerts and configuration."""
        return "JumboFrameDetector"

    def ingest(self, packet: ParsedPacket) -> None:
        """Tally an oversized frame against its source, at the packet's own time."""
        if packet.src_ip and packet.length > self.config.jumbo_bytes:
            self._counts.record(packet.src_ip, packet.timestamp.timestamp())

    def evaluate(self) -> list[DetectionAlert]:
        """Report each source newly over the threshold, once per episode."""
        alerts = []
        live: set[str] = set()
        for src_ip, count in self._counts.totals():
            live.add(src_ip)
            if not self.report_once(src_ip, count >= self.config.jumbo_count_threshold):
                continue
            alerts.append(
                self.emit_alert(
                    severity=Severity.LOW,
                    tactic=MitreTactic.RECONNAISSANCE,
                    src_ip=src_ip,
                    description=f"Jumbo frames: {count} oversized packets.",
                    evidence={"jumbo_count": count},
                )
            )
        self.forget_absent(live)
        return alerts
