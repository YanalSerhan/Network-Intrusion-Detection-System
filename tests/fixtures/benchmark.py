"""
Measurement helpers shared by the performance suite.

Data Setup:  Nothing — the helpers are pure timing utilities.
Data Input:  A callable to run, and how many items it processes.
Data Output: A Rate, and a printed line for the CI log.

Every floor in the performance suite is set well below what the code actually
achieves. The point of these tests is to catch an order-of-magnitude
regression — a per-packet allocation, an accidental O(n²) — not to certify a
number, because the number depends on whichever runner picked up the job.
"""

import time
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class Rate:
    """A throughput measurement over a fixed number of items."""

    count: int
    seconds: float

    @property
    def per_second(self) -> float:
        """Items processed per second; infinite if the run was too fast to time."""
        return self.count / self.seconds if self.seconds > 0 else float("inf")


def measure(count: int, work: Callable[[], Any]) -> Rate:
    """
    Time a callable that processes ``count`` items.

    Args:
        count: Number of items the callable handles.
        work:  The callable to time.

    Returns:
        The resulting Rate.
    """
    start = time.perf_counter()
    work()
    return Rate(count=count, seconds=time.perf_counter() - start)


def report(label: str, rate: Rate) -> None:
    """Print a measurement so a CI log shows the trend, not just pass/fail."""
    print(
        f"\n[benchmark] {label}: {rate.count:,} items in {rate.seconds:.3f}s "
        f"({rate.per_second:,.0f}/s)"
    )


def percentile(samples: Iterable[float], fraction: float) -> float:
    """
    Return the value below which the given fraction of samples fall.

    Nearest-rank rather than interpolated: with a few thousand samples the
    difference is noise, and the rank is easier to reason about when a
    threshold is missed.

    Args:
        samples:  Measured values.
        fraction: Between 0 and 1, e.g. 0.95 for p95.

    Returns:
        The sample at that rank.
    """
    ordered = sorted(samples)
    if not ordered:
        raise ValueError("percentile() needs at least one sample")
    index = min(len(ordered) - 1, int(round(fraction * len(ordered))) - 1)
    return ordered[max(index, 0)]
