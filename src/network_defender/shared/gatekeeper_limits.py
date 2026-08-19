"""
The part of the gatekeeper that decides whether a request may go out now.

Data Setup:  Constructed from a service's ServiceRateLimitConfig.
Data Input:  Callers entering and leaving the queue, and asking for a slot.
Data Output: Permission to proceed, or a GatekeeperError explaining the refusal.

Split from `gatekeeper`, which owns running the call, retrying it and logging
it. This file is the whole of the concurrency story: one lock guarding the
waiter count and both windows together, because separate locks would make each
check atomic and the pair of them racy — the failure mode that shape always
has. It genuinely runs concurrently: the enrichment worker thread and the
synchronous `/alerts/{id}/enrich` endpoint share one guard per service.
"""

import threading
import time

from .gatekeeper_models import QueueStatus
from .gatekeeper_window import DAY_SECONDS, WINDOW_SECONDS, FixedWindow
from .rate_limit_models import ServiceRateLimitConfig

#: How long a caller waits for a per-minute slot before being shed. One full
#: window: wait longer and the window has already rolled over, so a caller
#: still without a slot is competing with more traffic than the limit allows,
#: and shedding it is the honest answer.
MAX_WAIT_SECONDS = WINDOW_SECONDS

#: How often a waiting caller re-checks. Short enough not to overshoot the
#: window's end, long enough not to spin a core.
POLL_SECONDS = 0.1


class GatekeeperError(Exception):
    """Raised when the gatekeeper refuses a request rather than making it."""


class RateLimitGuard:
    """Admission control for one external service: queue depth and quotas."""

    def __init__(self, service_name: str, config: ServiceRateLimitConfig) -> None:
        """
        Initialise the guard.

        Args:
            service_name: Name of the service, used in refusal messages.
            config:       That service's rate-limit settings.
        """
        self._service_name = service_name
        self._config = config
        self._lock = threading.Lock()
        self._waiting = 0
        self._minute = FixedWindow(config.requests_per_minute, WINDOW_SECONDS)
        self._day = FixedWindow(config.requests_per_day, DAY_SECONDS)

    def enter_queue(self) -> None:
        """
        Take a place in the queue.

        Raises:
            GatekeeperError: If as many callers are already waiting as the
                configured depth allows, so this one is shed rather than
                added to an unbounded pile-up.
        """
        with self._lock:
            if self._waiting >= self._config.max_queue_depth:
                raise GatekeeperError(
                    f"[{self._service_name}] Queue full ({self._waiting} / "
                    f"{self._config.max_queue_depth}). Request rejected."
                )
            self._waiting += 1

    def leave_queue(self) -> None:
        """Give up this caller's place, whatever the outcome was."""
        with self._lock:
            self._waiting -= 1

    def acquire_slot(self) -> None:
        """
        Block until this request fits in both windows, or give up.

        Raises:
            GatekeeperError: If the daily quota is spent, or no per-minute slot
                came free within MAX_WAIT_SECONDS.
        """
        deadline = time.monotonic() + MAX_WAIT_SECONDS
        while True:
            with self._lock:
                if self._day.is_exhausted():
                    raise GatekeeperError(
                        f"[{self._service_name}] Daily quota of {self._day.limit} spent; "
                        f"resets in {self._day.seconds_until_reset():.0f}s."
                    )
                if not self._minute.is_exhausted():
                    self._minute.record()
                    self._day.record()
                    return
            if time.monotonic() >= deadline:
                raise GatekeeperError(
                    f"[{self._service_name}] No slot within {MAX_WAIT_SECONDS:.0f}s "
                    f"at {self._minute.limit}/min. Request shed."
                )
            time.sleep(POLL_SECONDS)

    def status(self) -> QueueStatus:
        """Return a snapshot of queue depth and both windows."""
        with self._lock:
            self._minute.refresh()
            self._day.refresh()
            return QueueStatus(
                service_name=self._service_name,
                queue_depth=self._waiting,
                max_queue_depth=self._config.max_queue_depth,
                is_backpressure_active=self._waiting >= self._config.max_queue_depth,
                requests_this_minute=self._minute.count,
                requests_per_minute_limit=self._minute.limit,
                requests_today=self._day.count,
                requests_per_day_limit=self._day.limit,
                seconds_until_daily_reset=self._day.seconds_until_reset(),
            )
