"""
Response headers that constrain what a browser will do with our output.

Data Setup:  Registered on the app by the factory.
Data Input:  Every outgoing response.
Data Output: The same response, with security headers set.

These are defence in depth rather than the primary control. The API returns
JSON and the dashboard is a React app that escapes what it renders, so none of
these headers is what stops an injection today — they are what limits the
damage if something else fails.

Not a Content-Security-Policy header with `unsafe-inline`: a policy that
permits inline script permits the thing it exists to prevent, and would be
worse than none for reading like protection. The dashboard is built by Vite
into hashed bundles with no inline script, so the policy below can be strict.
"""

from collections.abc import Awaitable, Callable

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response

#: Sent on every response.
#:
#: - `nosniff` stops a browser guessing that a JSON body is HTML, which is
#:   what would turn a reflected value into script.
#: - `DENY` stops the dashboard being framed for clickjacking; an operator
#:   clicking "disable rule" inside someone else's page is a real action.
#: - `no-referrer` keeps alert IDs and filter values out of the Referer header
#:   on any outbound link.
#: - The permissions policy turns off hardware a SOC dashboard never needs.
SECURITY_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=(), interest-cohort=()",
}

#: Content-Security-Policy. `default-src 'self'` covers scripts, styles and
#: fonts; `connect-src` additionally allows the WebSocket the live feed uses,
#: on the same origin. No `unsafe-inline` and no CDN.
CONTENT_SECURITY_POLICY = (
    "default-src 'self'; "
    "img-src 'self' data:; "
    "style-src 'self' 'unsafe-inline'; "
    "connect-src 'self' ws: wss:; "
    "frame-ancestors 'none'; "
    "base-uri 'self'; "
    "form-action 'self'"
)


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Adds the headers above to every response."""

    async def dispatch(
        self, request: Request, call_next: Callable[[Request], Awaitable[Response]]
    ) -> Response:
        """
        Set security headers on the way out.

        Args:
            request:   The incoming request.
            call_next: The rest of the middleware chain.

        Returns:
            The response, with headers added.
        """
        response = await call_next(request)
        for header, value in SECURITY_HEADERS.items():
            response.headers.setdefault(header, value)
        response.headers.setdefault("Content-Security-Policy", CONTENT_SECURITY_POLICY)
        return response
