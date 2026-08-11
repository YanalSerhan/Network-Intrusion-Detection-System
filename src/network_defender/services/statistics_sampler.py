"""
Statistics sampling.

Data Setup:  Holds the previous sample so throughput can be derived.
Data Input:  Cumulative capture counters and alert aggregates.
Data Output: One StatisticsRecord per tick.

Why a sampler rather than a direct write
----------------------------------------
`packets_captured` is a cumulative counter, but the chart needs a *rate*.
Recording the counter alone produced snapshots with `packets_per_second = 0`
forever — a flat zero line no matter how much traffic passed. Rate has to be
derived from the delta between consecutive samples, which means something must
remember the previous one.

Counter resets are handled explicitly: capture restarting sets the cumulative
count back to zero, and a naive subtraction would yield a large negative rate.
"""

import time
from typing import Any

from ..shared.base import LoggableMixin


class StatisticsSampler(LoggableMixin):
    """Derives per-second throughput from cumulative capture counters."""

    def __init__(self) -> None:
        """Initialise with no previous sample."""
        self._last_packets: int | None = None
        self._last_time: float | None = None

    def reset(self) -> None:
        """Forget the previous sample, so the next tick starts a new baseline."""
        self._last_packets = None
        self._last_time = None

    def sample(self, total_packets: int, now: float | None = None) -> float:
        """
        Return packets per second since the previous sample.

        Args:
            total_packets: Cumulative packets captured since the sensor started.
            now:           Monotonic timestamp; injectable for tests.

        Returns:
            Packets per second, or 0.0 for the first sample and after a reset.
        """
        current_time = now if now is not None else time.monotonic()
        previous_packets, previous_time = self._last_packets, self._last_time

        self._last_packets = total_packets
        self._last_time = current_time

        # First sample: no interval to divide by yet.
        if previous_packets is None or previous_time is None:
            return 0.0

        elapsed = current_time - previous_time
        if elapsed <= 0:
            return 0.0

        delta = total_packets - previous_packets
        if delta < 0:
            # The capture service restarted and its counter went back to zero.
            # Reporting a negative rate would put a spike through the chart, so
            # this sample is treated as a new baseline instead.
            self.logger.info("Capture counter reset; restarting throughput baseline.")
            return 0.0

        return round(delta / elapsed, 2)


def build_snapshot_payload(
    total_packets: int,
    packets_per_second: float,
    alert_stats: dict[str, Any],
    top_talkers: dict[str, int],
) -> dict[str, Any]:
    """
    Assemble the keyword arguments for one statistics snapshot.

    Args:
        total_packets:      Cumulative packets captured.
        packets_per_second: Derived throughput for this interval.
        alert_stats:        Output of `SDK.get_alert_statistics()`.
        top_talkers:        Busiest source addresses and their alert counts.

    Returns:
        Keyword arguments for `StatisticsRepository.record_snapshot`.
    """
    return {
        "total_packets": total_packets,
        "total_alerts": alert_stats["total_alerts"],
        "packets_per_second": packets_per_second,
        "alerts_by_severity": alert_stats["by_severity"],
        "top_talkers": top_talkers,
    }
