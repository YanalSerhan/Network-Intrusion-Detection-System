"""
Request correlation and access logging.

Data Setup:  Registered on the app by the factory.
Data Input:  Incoming HTTP requests.
Data Output: A correlation ID per request, echoed to the client, plus one
             structured access log line per request.

An inbound `X-Correlation-ID` is honoured rather than overwritten, so a trace
started by a reverse proxy or a calling service continues through this one
instead of restarting at the edge. The ID is echoed in the response header so a
user reporting a problem can quote it and an operator can find the exact
request.

Query strings are deliberately not logged: filters carry IP addresses, and the
WebSocket handshake carries the API key as `?token=`. Logging the path alone
keeps the access log useful without turning it into a credential store.
"""

import time
from collections.abc import Awaitable, Callable

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response

from ..observability import correlation_scope, get_correlation_id
from ..observability.logging_setup import get_audit_logger

CORRELATION_HEADER = "X-Correlation-ID"

#: Paths excluded from access logging. Orchestrator probes run every few
#: seconds and would otherwise dominate the log with no diagnostic value.
QUIET_PATHS = frozenset({"/api/v1/health", "/api/v1/health/live"})


class CorrelationMiddleware(BaseHTTPMiddleware):
    """Assigns a correlation ID to each request and logs the outcome."""

    async def dispatch(
        self, request: Request, call_next: Callable[[Request], Awaitable[Response]]
    ) -> Response:
        """
        Run one request inside a correlation scope.

        Args:
            request:   The incoming request.
            call_next: The next handler in the chain.

        Returns:
            The response, with the correlation ID attached.
        """
        inbound = request.headers.get(CORRELATION_HEADER)

        with correlation_scope(inbound):
            started = time.perf_counter()
            try:
                response = await call_next(request)
            except Exception:
                # The error handlers turn this into a 500 response; logging it
                # here keeps the failure attached to its correlation ID.
                self._log(request, status=500, elapsed=time.perf_counter() - started)
                raise

            self._log(request, response.status_code, time.perf_counter() - started)
            correlation_id = get_correlation_id()
            if correlation_id:
                response.headers[CORRELATION_HEADER] = correlation_id
            return response

    @staticmethod
    def _log(request: Request, status: int, elapsed: float) -> None:
        """Emit one structured access record, skipping health probes."""
        if request.url.path in QUIET_PATHS:
            return

        get_audit_logger().info(
            "HTTP request",
            extra={
                "event": "http_request",
                "method": request.method,
                # Path only — query strings carry addresses and, on the
                # WebSocket handshake, the API key.
                "path": request.url.path,
                "status": status,
                "duration_ms": round(elapsed * 1000, 2),
                "client": request.client.host if request.client else None,
            },
        )
