"""
Beaconing detector.

Data Setup:  Thresholds from config/detectors.json.
Data Input:  Outbound TCP/HTTP/TLS packets.
Data Output: Alerts for destinations contacted at suspiciously regular intervals.

Malware calling home tends to do so on a timer. Low variance in the interval
between connections is the signal; ordinary human-driven traffic is bursty.
"""

import math
from collections import defaultdict

from pydantic import Field

from network_defender.constants import MitreTactic, Protocol, Severity
from network_defender.detectors.base import BaseDetector
from network_defender.detectors.models import DetectionAlert, DetectorConfig
from network_defender.parser.models import ParsedPacket


class BeaconingConfig(DetectorConfig):
    time_window_seconds: int = Field(default=3600)
    connection_count_threshold: int = Field(default=10)
    interval_variance_tolerance: float = Field(default=0.1)

class BeaconingDetector(BaseDetector[BeaconingConfig]):
    def __init__(self, config: BeaconingConfig) -> None:
        super().__init__(config)
        self._src_dst_timestamps: defaultdict[tuple[str, str], list[float]] = defaultdict(list)

    @property
    def name(self) -> str:
        return "BeaconingDetector"

    def ingest(self, packet: ParsedPacket) -> None:
        beaconable = (Protocol.TCP, Protocol.HTTP, Protocol.TLS)
        if packet.protocol in beaconable and packet.src_ip and packet.dst_ip:
            key = (packet.src_ip, packet.dst_ip)
            self._src_dst_timestamps[key].append(packet.timestamp.timestamp())

    def evaluate(self) -> list[DetectionAlert]:
        alerts = []
        for (src_ip, dst_ip), timestamps in self._src_dst_timestamps.items():
            if len(timestamps) >= self.config.connection_count_threshold:
                # Sort first: out-of-order arrivals produce negative intervals,
                # which inflate the standard deviation and mask real beacons.
                ordered = sorted(timestamps)
                intervals = [ordered[i] - ordered[i - 1] for i in range(1, len(ordered))]
                if len(intervals) > 0:
                    mean_interval = sum(intervals) / len(intervals)
                    if mean_interval > 0:
                        variance = sum((x - mean_interval)**2 for x in intervals) / len(intervals)
                        std_dev = math.sqrt(variance)

                        if (std_dev / mean_interval) <= self.config.interval_variance_tolerance:
                            alerts.append(
                                self.emit_alert(
                                    severity=Severity.HIGH,
                                    tactic=MitreTactic.COMMAND_AND_CONTROL,
                                    src_ip=src_ip,
                                    dst_ip=dst_ip,
                                    description=(
                                        "Possible Beaconing detected: regular "
                                        "connections to same destination."
                                    ),
                                    evidence={
                                        "mean_interval": mean_interval,
                                        "connection_count": len(timestamps),
                                    },
                                )
                            )
        self._src_dst_timestamps.clear()
        return alerts
