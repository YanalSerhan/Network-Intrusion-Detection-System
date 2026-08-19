"""
Tests that the gatekeeper sheds load instead of piling it up.

Both cases were defects the Milestone 15 review found. The queue was appended
to and popped in the same breath, so its depth never exceeded one and the
configured maximum was unreachable — meaning backpressure could not fire and a
caller that could not get a slot slept in an unbounded loop instead. And the
window had no lock, though the enrichment worker thread and the synchronous
/enrich endpoint share one gatekeeper per service.
"""

import threading
import time

import pytest

from network_defender.shared.gatekeeper import GatekeeperError
from network_defender.shared.gatekeeper_limits import RateLimitGuard
from network_defender.shared.rate_limit_models import ServiceRateLimitConfig


def _config(**overrides: object) -> ServiceRateLimitConfig:
    """Build a rate-limit config with fast, test-friendly defaults."""
    fields: dict[str, object] = {
        "requests_per_minute": 5,
        "requests_per_day": 100,
        "max_queue_depth": 4,
        "retry_attempts": 0,
        "retry_backoff_base_seconds": 0.01,
    }
    fields.update(overrides)
    return ServiceRateLimitConfig(**fields)  # type: ignore[arg-type]


def test_a_caller_is_shed_rather_than_blocking_forever() -> None:
    """
    Waiting without a deadline is the opposite of backpressure.

    A caller that cannot get a slot used to sleep in a loop with no way out,
    so an alert storm stalled the enrichment worker indefinitely instead of
    shedding work and staying responsive.
    """
    guard = RateLimitGuard("svc", _config(requests_per_minute=1))
    guard.acquire_slot()  # take the only slot this minute

    from network_defender.shared import gatekeeper_limits

    original = gatekeeper_limits.MAX_WAIT_SECONDS
    gatekeeper_limits.MAX_WAIT_SECONDS = 0.2
    try:
        started = time.monotonic()
        with pytest.raises(GatekeeperError, match="No slot within"):
            guard.acquire_slot()
        assert time.monotonic() - started < 5.0
    finally:
        gatekeeper_limits.MAX_WAIT_SECONDS = original


def test_the_queue_fills_with_real_waiting_callers() -> None:
    """
    max_queue_depth has to be reachable, or backpressure is decorative.

    The old queue was appended to and popped in the same breath, so its depth
    never exceeded one and the configured maximum could not be hit.
    """
    guard = RateLimitGuard("svc", _config(max_queue_depth=2))

    guard.enter_queue()
    guard.enter_queue()
    assert guard.status().queue_depth == 2
    assert guard.status().is_backpressure_active is True

    with pytest.raises(GatekeeperError, match="Queue full"):
        guard.enter_queue()

    guard.leave_queue()
    guard.enter_queue()  # a place came free


def test_concurrent_callers_cannot_exceed_the_limit() -> None:
    """
    The worker thread and the synchronous /enrich endpoint share one guard.

    Without a lock both could pass the "is the window full?" check before
    either recorded, so the configured limit was advisory under exactly the
    conditions it was meant to hold. Ten threads ask for three slots each
    against a limit of twenty; the losers must be refused, not admitted.
    """
    from network_defender.shared import gatekeeper_limits

    limit = 20
    guard = RateLimitGuard("svc", _config(requests_per_minute=limit, max_queue_depth=100))
    granted: list[bool] = []
    lock = threading.Lock()
    barrier = threading.Barrier(10)

    def _race() -> None:
        barrier.wait()
        for _ in range(3):
            try:
                guard.acquire_slot()
            except GatekeeperError:
                return
            with lock:
                granted.append(True)

    original = gatekeeper_limits.MAX_WAIT_SECONDS
    gatekeeper_limits.MAX_WAIT_SECONDS = 0.2  # losers give up instead of waiting out the window
    try:
        threads = [threading.Thread(target=_race) for _ in range(10)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=30)
            assert not thread.is_alive(), "a caller never returned"
    finally:
        gatekeeper_limits.MAX_WAIT_SECONDS = original

    assert len(granted) == limit, f"{len(granted)} slots granted against a limit of {limit}"
    assert guard.status().requests_this_minute == limit
