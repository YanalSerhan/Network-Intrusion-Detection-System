"""
Correlation IDs.

Data Setup:  A single ContextVar; no configuration.
Data Input:  IDs set at the start of a traceable unit of work.
Data Output: The current ID, read by the log formatter.

What gets an ID
---------------
One per **detection event** and one per **HTTP request** — not one per packet.
At the 10k pps target, minting a UUID for every packet would mean 10,000 IDs a
second for traffic that is almost entirely discarded, and the resulting logs
would be untraceable by volume alone. An ID starts when a detector or rule
fires and follows that finding through scoring, deduplication, persistence,
notification and enrichment, which is the path an analyst actually retraces.

Threads
-------
`ContextVar` is not inherited by `threading.Thread`; a worker started from a
request would silently log without an ID. The pipeline crosses thread
boundaries three times (capture callback, evaluation loop, enrichment worker),
so `bind_correlation_id` exists to carry an ID explicitly across a hand-off.
"""

import uuid
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from contextvars import ContextVar
from functools import wraps
from typing import Any

_correlation_id: ContextVar[str | None] = ContextVar("correlation_id", default=None)


def new_correlation_id() -> str:
    """Return a fresh correlation ID. Short form: full UUIDs bloat every line."""
    return uuid.uuid4().hex[:16]


def get_correlation_id() -> str | None:
    """Return the correlation ID for the current context, if any."""
    return _correlation_id.get()


def set_correlation_id(correlation_id: str | None) -> None:
    """
    Set the correlation ID for the current context.

    Args:
        correlation_id: The ID to set, or None to clear it.
    """
    _correlation_id.set(correlation_id)


@contextmanager
def correlation_scope(correlation_id: str | None = None) -> Iterator[str]:
    """
    Run a block under a correlation ID, restoring the previous one after.

    The token-based reset matters for nesting: an enrichment scope inside a
    request scope must hand the request's ID back when it finishes, not clear
    it and leave the rest of the request untraceable.

    Args:
        correlation_id: ID to use; a new one is minted when omitted.

    Yields:
        The active correlation ID.
    """
    resolved = correlation_id or new_correlation_id()
    token = _correlation_id.set(resolved)
    try:
        yield resolved
    finally:
        _correlation_id.reset(token)


def bind_correlation_id(func: Callable[..., Any]) -> Callable[..., Any]:
    """
    Capture the current correlation ID and re-apply it when `func` runs later.

    Wrap a callable before handing it to a thread or queue; without this the
    work would execute under a fresh context and lose the trace.

    Args:
        func: The callable to wrap.

    Returns:
        The wrapped callable.
    """
    captured = get_correlation_id()

    @wraps(func)
    def wrapper(*args: Any, **kwargs: Any) -> Any:
        with correlation_scope(captured):
            return func(*args, **kwargs)

    return wrapper
