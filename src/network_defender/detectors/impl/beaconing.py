"""
Beaconing detector.

Data Setup:  Thresholds from config/detectors.json.
Data Input:  Outbound TCP/HTTP/TLS packets.
Data Output: Alerts for destinations contacted at suspiciously regular intervals.

Malware calling home tends to do so on a timer. Low variance in the interval
between connections is the signal; ordinary human-driven traffic is bursty.
"""

import math

from pydantic import Field

from network_defender.constants import MitreTactic, Protocol, Severity
from network_defender.detectors.base import BaseDetector
from network_defender.detectors.models import DetectionAlert, DetectorConfig
from network_defender.detectors.window_timestamps import SlidingTimestamps
from network_defender.parser.models import ParsedPacket

#: Joins a source and destination into one key. Neither can contain it, so the
#: pair is recoverable and no second mapping has to be kept in step.
CONVERSATION = "|"


class BeaconingConfig(DetectorConfig):
    """Tunables for the beaconing detector."""

    time_window_seconds: int = Field(default=3600)
    connection_count_threshold: int = Field(default=10)
    #: Coefficient of variation (standard deviation over mean) at or below
    #: which intervals count as regular. A ratio rather than an absolute
    #: tolerance, so a beacon every hour and one every ten seconds are held to
    #: the same standard of regularity.
    interval_variance_tolerance: float = Field(default=0.1)


class BeaconingDetector(BaseDetector[BeaconingConfig]):
    """
    Detects a host contacting one destination on a regular timer.

    Regularity, not volume, is the finding: malware calling home runs on a
    schedule, while human-driven traffic is bursty. The window is an hour by
    default because a beacon with a long interval needs a long window before
    there are enough samples for the variance to mean anything.
    """

    def __init__(self, config: BeaconingConfig) -> None:
        """Initialise with the validated connection count and tolerance."""
        super().__init__(config)
        self._conversations = SlidingTimestamps(self.window_seconds)

    @property
    def name(self) -> str:
        """Detector name used in alerts and configuration."""
        return "BeaconingDetector"

    def ingest(self, packet: ParsedPacket) -> None:
        """Record when this source last reached this destination."""
        beaconable = (Protocol.TCP, Protocol.HTTP, Protocol.TLS)
        if packet.protocol in beaconable and packet.src_ip and packet.dst_ip:
            self._conversations.record(
                f"{packet.src_ip}{CONVERSATION}{packet.dst_ip}", packet.timestamp.timestamp()
            )

    def _mean_interval(self, times: tuple[float, ...]) -> float | None:
        """
        Return the mean gap between connections, if it reads as a timer.

        Args:
            times: Ascending capture times for one conversation.

        Returns:
            The mean interval when its coefficient of variation is inside the
            configured tolerance, else None.
        """
        if len(times) < self.config.connection_count_threshold:
            return None
        intervals = [later - earlier for earlier, later in zip(times, times[1:], strict=False)]
        mean = sum(intervals) / len(intervals) if intervals else 0.0
        if mean <= 0:
            return None
        variance = sum((gap - mean) ** 2 for gap in intervals) / len(intervals)
        if math.sqrt(variance) / mean > self.config.interval_variance_tolerance:
            return None
        return mean

    def evaluate(self) -> list[DetectionAlert]:
        """Report each conversation that has newly started running on a timer."""
        alerts = []
        live: set[str] = set()
        for key, times in self._conversations.entries():
            live.add(key)
            mean = self._mean_interval(times)
            if not self.report_once(key, mean is not None) or mean is None:
                continue
            src_ip, dst_ip = key.split(CONVERSATION, 1)
            alerts.append(
                self.emit_alert(
                    severity=Severity.HIGH,
                    tactic=MitreTactic.COMMAND_AND_CONTROL,
                    src_ip=src_ip,
                    dst_ip=dst_ip,
                    description=(
                        "Possible Beaconing detected: regular connections to same destination."
                    ),
                    evidence={"mean_interval": mean, "connection_count": len(times)},
                )
            )
        self.forget_absent(live)
        return alerts
