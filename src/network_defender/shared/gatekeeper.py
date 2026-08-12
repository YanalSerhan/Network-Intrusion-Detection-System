"""
Centralized API Gatekeeper for all outbound external API calls.

IMPORTANT: No code in Network Defender may call an external API directly.
All outbound calls MUST be routed through ApiGatekeeper.execute().

Data Setup:  Instantiated with a ServiceRateLimitConfig per service.
Data Input:  A callable (the API call) plus its args/kwargs.
Data Output: The return value of the callable, or raises GatekeeperError.
"""

import logging
import time
from collections import deque
from collections.abc import Callable
from typing import Any

from .gatekeeper_models import QueueStatus
from .gatekeeper_window import MinuteWindow
from .rate_limit_models import ServiceRateLimitConfig

logger = logging.getLogger("network_defender.audit")


class GatekeeperError(Exception):
    """Raised when the gatekeeper rejects a request due to backpressure or exhausted retries."""


class ApiGatekeeper:
    """
    Mediates outbound API calls: rate limiting, FIFO queuing, backpressure,
    retry-with-backoff and structured logging.

    Usage:
        gatekeeper = ApiGatekeeper(service_name="abuseipdb", config=cfg)
        result = gatekeeper.execute(my_api_fn, ip_address="1.2.3.4")
    """

    def __init__(self, service_name: str, config: ServiceRateLimitConfig) -> None:
        """
        Initialise the gatekeeper for a specific external service.

        Args:
            service_name: Human-readable name of the external service (used in logs).
            config: Rate-limit settings for this service.
        """
        self._service_name = service_name
        self._config = config
        self._queue: deque[Callable[[], Any]] = deque()
        self._window = MinuteWindow(config.requests_per_minute)

    def execute(self, api_call: Callable[..., Any], *args: Any, **kwargs: Any) -> Any:
        """
        Execute an external API call, enforcing rate limits and retries.

        Args:
            api_call: The callable that performs the outbound HTTP request.
            *args:    Positional arguments forwarded to api_call.
            **kwargs: Keyword arguments forwarded to api_call.

        Returns:
            The return value of api_call.

        Raises:
            GatekeeperError: If the queue is full (backpressure) or all retries exhausted.
        """
        if self._is_backpressure_active():
            raise GatekeeperError(
                f"[{self._service_name}] Queue full ({len(self._queue)} / "
                f"{self._config.max_queue_depth}). Request rejected."
            )

        bound_call: Callable[[], Any] = lambda: api_call(*args, **kwargs)  # noqa: E731
        self._queue.append(bound_call)
        return self._dispatch_next()

    def get_queue_status(self) -> QueueStatus:
        """Return a snapshot of the current queue state for monitoring."""
        self._window.refresh()
        return QueueStatus(
            service_name=self._service_name,
            queue_depth=len(self._queue),
            max_queue_depth=self._config.max_queue_depth,
            is_backpressure_active=self._is_backpressure_active(),
            requests_this_minute=self._window.count,
            requests_per_minute_limit=self._config.requests_per_minute,
        )

    def _dispatch_next(self) -> Any:
        """Pop the next call from the queue, apply rate limiting, and execute with retries."""
        if not self._queue:
            raise GatekeeperError(f"[{self._service_name}] Queue is unexpectedly empty.")

        bound_call = self._queue.popleft()
        self._window.wait_for_slot()
        return self._execute_with_retry(bound_call)

    def _execute_with_retry(self, bound_call: Callable[[], Any]) -> Any:
        """Execute a bound call with exponential backoff on transient failures."""
        last_exc: Exception | None = None
        for attempt in range(self._config.retry_attempts + 1):
            start = time.monotonic()
            try:
                result = bound_call()
                latency = time.monotonic() - start
                self._log_call(success=True, latency=latency, attempt=attempt)
                self._window.record()
                return result
            except Exception as exc:
                latency = time.monotonic() - start
                last_exc = exc
                self._log_call(success=False, latency=latency, attempt=attempt, error=str(exc))
                if attempt < self._config.retry_attempts:
                    sleep_secs = self._config.retry_backoff_base_seconds * (2**attempt)
                    time.sleep(sleep_secs)

        raise GatekeeperError(
            f"[{self._service_name}] All {self._config.retry_attempts} retries exhausted."
        ) from last_exc

    def _is_backpressure_active(self) -> bool:
        """Return True when the queue is at or beyond its maximum depth."""
        return len(self._queue) >= self._config.max_queue_depth

    def _log_call(
        self,
        success: bool,
        latency: float,
        attempt: int,
        error: str | None = None,
    ) -> None:
        """Emit a structured audit log entry for every outbound API call."""
        logger.info(
            "Outbound API call",
            extra={
                "service": self._service_name,
                "success": success,
                "latency_seconds": round(latency, 4),
                "attempt": attempt,
                "error": error,
            },
        )
