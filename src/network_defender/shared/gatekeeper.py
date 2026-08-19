"""
Centralized API Gatekeeper for all outbound external API calls.

IMPORTANT: No code in Network Defender may call an external API directly.
All outbound calls MUST be routed through ApiGatekeeper.execute().

Data Setup:  Instantiated with a ServiceRateLimitConfig per service.
Data Input:  A callable (the API call) plus its args/kwargs.
Data Output: The return value of the callable, or raises GatekeeperError.

Admission control — queue depth, per-minute and per-day windows, and the lock
holding them together — lives in `gatekeeper_limits`. This file owns running
the call: acquiring a slot for every attempt, retrying with backoff, and
writing one audit record per attempt.
"""

import logging
import time
from collections.abc import Callable
from typing import Any

from .gatekeeper_limits import GatekeeperError, RateLimitGuard
from .gatekeeper_models import QueueStatus
from .rate_limit_models import ServiceRateLimitConfig

logger = logging.getLogger("network_defender.audit")

__all__ = ["ApiGatekeeper", "GatekeeperError"]


class ApiGatekeeper:
    """
    The single door every outbound API call goes through.

    Rate limiting, queuing, backpressure, retry-with-backoff and structured
    logging, in one place — because a rate limit enforced in nine call sites
    is a rate limit enforced in eight call sites.

    Usage:
        gatekeeper = ApiGatekeeper(service_name="abuseipdb", config=cfg)
        result = gatekeeper.execute(my_api_fn, ip_address="1.2.3.4")
    """

    def __init__(self, service_name: str, config: ServiceRateLimitConfig) -> None:
        """
        Initialise the gatekeeper for a specific external service.

        Args:
            service_name: Human-readable name of the service (used in logs).
            config:       Rate-limit settings for this service.
        """
        self._service_name = service_name
        self._config = config
        self._guard = RateLimitGuard(service_name, config)

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
            GatekeeperError: If the queue is full, the daily quota is spent,
                no slot came free in time, or every attempt failed.
        """
        self._guard.enter_queue()
        try:
            return self._execute_with_retry(lambda: api_call(*args, **kwargs))
        finally:
            self._guard.leave_queue()

    def get_queue_status(self) -> QueueStatus:
        """Return a snapshot of the current state for monitoring."""
        return self._guard.status()

    def _execute_with_retry(self, bound_call: Callable[[], Any]) -> Any:
        """
        Execute a bound call, retrying with exponential backoff.

        A slot is acquired before *every* attempt, retries included. A failed
        request still reached the provider, and an HTTP 429 is precisely the
        case rate limiting exists to avoid making worse — counting only
        successes would let an outage fire every retry for free.
        """
        last_exc: Exception | None = None
        for attempt in range(self._config.retry_attempts + 1):
            self._guard.acquire_slot()
            start = time.monotonic()
            try:
                result = bound_call()
                self._log_call(True, time.monotonic() - start, attempt)
                return result
            except Exception as exc:
                last_exc = exc
                self._log_call(False, time.monotonic() - start, attempt, str(exc))
                if attempt < self._config.retry_attempts:
                    time.sleep(self._config.retry_backoff_base_seconds * (2**attempt))

        raise GatekeeperError(
            f"[{self._service_name}] All {self._config.retry_attempts} retries exhausted."
        ) from last_exc

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
