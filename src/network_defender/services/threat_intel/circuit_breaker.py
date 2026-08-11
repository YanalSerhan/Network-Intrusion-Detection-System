"""
Per-provider circuit breaker.

Data Setup:  Failure threshold and reset timeout injected via __init__.
Data Input:  Success/failure signals from provider lookups.
Data Output: Whether a provider may be called right now.

States
------
    CLOSED    normal operation; failures are counted
    OPEN      provider is cut out; calls short-circuit immediately
    HALF_OPEN one trial call is allowed after the reset timeout

Why this exists
---------------
When a provider goes down, every lookup pays the full HTTP timeout and then
burns all its retries. With a 10s timeout and 3 retries that is ~40 seconds per
alert, spent entirely on a service that is known to be failing. The breaker
converts that into an immediate skip, which is what "fail open" requires: keep
raising alerts, just without enrichment from that source.
"""

import threading
import time

from network_defender.constants import TI_BREAKER_FAILURE_THRESHOLD, TI_BREAKER_RESET_SECONDS

STATE_CLOSED = "closed"
STATE_OPEN = "open"
STATE_HALF_OPEN = "half_open"


class CircuitBreaker:
    """Trips after consecutive failures; retries a single call after a cooldown."""

    def __init__(
        self,
        failure_threshold: int = TI_BREAKER_FAILURE_THRESHOLD,
        reset_seconds: float = TI_BREAKER_RESET_SECONDS,
    ) -> None:
        """
        Initialise the breaker.

        Args:
            failure_threshold: Consecutive failures before opening the circuit.
            reset_seconds:     Cooldown before a trial call is allowed through.

        Raises:
            ValueError: If failure_threshold is not positive.
        """
        if failure_threshold <= 0:
            raise ValueError("failure_threshold must be greater than zero.")
        self._threshold = failure_threshold
        self._reset_seconds = reset_seconds
        self._failures = 0
        self._opened_at: float | None = None
        self._lock = threading.Lock()

    @property
    def state(self) -> str:
        """Current breaker state, accounting for an elapsed cooldown."""
        with self._lock:
            return self._state_unlocked()

    @property
    def consecutive_failures(self) -> int:
        """Number of consecutive failures recorded since the last success."""
        with self._lock:
            return self._failures

    def allows_request(self) -> bool:
        """
        Return True if a call may proceed.

        Open circuits reject until the cooldown elapses, after which a single
        trial call is admitted (half-open).
        """
        with self._lock:
            return self._state_unlocked() != STATE_OPEN

    def record_success(self) -> None:
        """Reset the breaker after a successful call."""
        with self._lock:
            self._failures = 0
            self._opened_at = None

    def record_failure(self) -> None:
        """Count a failure and open the circuit once the threshold is reached."""
        with self._lock:
            self._failures += 1
            if self._failures >= self._threshold:
                self._opened_at = time.monotonic()

    def reset(self) -> None:
        """Force the breaker closed (used on restart and in tests)."""
        with self._lock:
            self._failures = 0
            self._opened_at = None

    def _state_unlocked(self) -> str:
        """Compute the current state; caller must hold the lock."""
        if self._opened_at is None:
            return STATE_CLOSED
        if (time.monotonic() - self._opened_at) >= self._reset_seconds:
            return STATE_HALF_OPEN
        return STATE_OPEN
