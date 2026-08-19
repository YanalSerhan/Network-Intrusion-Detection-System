"""
A detector that records how the harness drove it.

Substituting a real detector here would test the detector as much as the
harness; this one only remembers how many packets each evaluation saw, which
is exactly the harness's contract.
"""

from network_defender.constants import Severity
from network_defender.detectors.base import BaseDetector
from network_defender.detectors.models import DetectionAlert, DetectorConfig
from network_defender.parser.models import ParsedPacket


class RecordingDetector(BaseDetector[DetectorConfig]):
    """Records the size of each evaluation batch."""

    def __init__(self, alert_on_every_evaluation: bool = False) -> None:
        """Initialise with default configuration and empty history."""
        super().__init__(DetectorConfig())
        self.batches: list[int] = []
        self._pending = 0
        self._always_alert = alert_on_every_evaluation

    @property
    def name(self) -> str:
        """Detector name used in alerts."""
        return "RecordingDetector"

    def ingest(self, packet: ParsedPacket) -> None:
        """Count the packet against the current window."""
        del packet
        self._pending += 1

    def evaluate(self) -> list[DetectionAlert]:
        """Record the batch size, clear the window, and optionally alert."""
        if self._pending or self._always_alert:
            self.batches.append(self._pending)
        self._pending = 0
        if not self._always_alert:
            return []
        return [self.emit_alert(severity=Severity.LOW, description="recorded")]
