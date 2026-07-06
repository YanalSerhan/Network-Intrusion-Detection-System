"""
Token-bucket rate limiter for capture backpressure.

Data Setup:  Constructed with a packets_per_second rate and optional burst capacity.
Data Input:  Repeated calls to acquire() from the packet callback thread.
Data Output: Boolean allow/deny decision; backpressure_active property for monitoring.

The token-bucket algorithm allows short bursts up to `burst` tokens while
enforcing a long-run average of `rate` tokens per second. When the bucket is
empty, acquire() returns False and backpressure is signalled.
"""

import threading
import time

from ..constants import DEFAULT_PACKETS_PER_SECOND


class CaptureRateLimiter:
    """
    Thread-safe token-bucket rate limiter.

    Single responsibility: decide whether a packet should be admitted or
    dropped based on the configured arrival rate.

    Data Setup:  rate_pps and burst are injected at construction time.
    Data Input:  acquire() calls from one or more producer threads.
    Data Output: True (admit) / False (drop) per acquire() call.
    """

    def __init__(
        self,
        rate_pps: int = DEFAULT_PACKETS_PER_SECOND,
        burst: int = 0,
    ) -> None:
        """
        Initialise the token bucket.

        Args:
            rate_pps: Target packets per second (token refill rate). 0 = unlimited.
            burst:    Maximum token burst above the steady-state capacity.
                      Defaults to rate_pps (1-second burst allowance).
        """
        self._rate = rate_pps
        self._burst = burst if burst > 0 else max(rate_pps, 1)
        self._tokens: float = float(self._burst)
        self._last_refill = time.monotonic()
        self._lock = threading.Lock()
        self._dropped: int = 0

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def acquire(self) -> bool:
        """
        Attempt to consume one token.

        Returns:
            True if the packet is admitted; False if the bucket is empty
            and the packet should be dropped.
        """
        if self._rate == 0:
            return True  # unlimited mode

        with self._lock:
            self._refill()
            if self._tokens >= 1.0:
                self._tokens -= 1.0
                return True
            self._dropped += 1
            return False

    @property
    def backpressure_active(self) -> bool:
        """True when the bucket is currently empty (last acquire() failed)."""
        with self._lock:
            self._refill()
            return self._tokens < 1.0

    @property
    def packets_dropped(self) -> int:
        """Total number of packets dropped since construction."""
        with self._lock:
            return self._dropped

    def reset(self) -> None:
        """Reset the bucket to full capacity and clear the drop counter."""
        with self._lock:
            self._tokens = float(self._burst)
            self._last_refill = time.monotonic()
            self._dropped = 0

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _refill(self) -> None:
        """Add tokens proportional to elapsed time since the last refill."""
        now = time.monotonic()
        elapsed = now - self._last_refill
        self._last_refill = now
        new_tokens = elapsed * self._rate
        self._tokens = min(self._tokens + new_tokens, float(self._burst))
