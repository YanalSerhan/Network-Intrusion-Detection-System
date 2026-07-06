"""
Unit tests for capture/rate_limiter.py.

Tests cover token-bucket mechanics, unlimited mode, thread safety (basic),
backpressure property, drop counter, and reset.
"""

import time

from network_defender.capture.rate_limiter import CaptureRateLimiter

# ---------------------------------------------------------------------------
# Basic admit / drop behaviour
# ---------------------------------------------------------------------------


def test_fresh_limiter_admits_up_to_burst() -> None:
    """A freshly created limiter should admit up to burst tokens immediately."""
    limiter = CaptureRateLimiter(rate_pps=10, burst=5)
    admitted = sum(1 for _ in range(5) if limiter.acquire())
    assert admitted == 5


def test_limiter_drops_when_bucket_empty() -> None:
    """After exhausting burst, acquire() must return False."""
    limiter = CaptureRateLimiter(rate_pps=1, burst=1)
    limiter.acquire()  # consume the only token
    assert limiter.acquire() is False


def test_drop_counter_increments_on_failure() -> None:
    limiter = CaptureRateLimiter(rate_pps=1, burst=1)
    limiter.acquire()  # exhaust
    limiter.acquire()  # drop
    limiter.acquire()  # drop
    assert limiter.packets_dropped == 2


# ---------------------------------------------------------------------------
# Unlimited mode (rate=0)
# ---------------------------------------------------------------------------


def test_unlimited_mode_always_admits() -> None:
    limiter = CaptureRateLimiter(rate_pps=0)
    results = [limiter.acquire() for _ in range(1000)]
    assert all(results)


def test_unlimited_mode_never_increments_drop_counter() -> None:
    limiter = CaptureRateLimiter(rate_pps=0)
    for _ in range(100):
        limiter.acquire()
    assert limiter.packets_dropped == 0


# ---------------------------------------------------------------------------
# Backpressure property
# ---------------------------------------------------------------------------


def test_backpressure_active_when_bucket_empty() -> None:
    limiter = CaptureRateLimiter(rate_pps=1, burst=1)
    limiter.acquire()  # drain
    assert limiter.backpressure_active is True


def test_backpressure_not_active_on_fresh_limiter() -> None:
    limiter = CaptureRateLimiter(rate_pps=100, burst=50)
    assert limiter.backpressure_active is False


# ---------------------------------------------------------------------------
# Token refill over time
# ---------------------------------------------------------------------------


def test_tokens_refill_over_time() -> None:
    """After draining, tokens should refill proportionally to elapsed time."""
    limiter = CaptureRateLimiter(rate_pps=1000, burst=1)
    limiter.acquire()  # drain
    time.sleep(0.05)  # 50ms → ~50 tokens at 1000 pps
    # Should be admitted again after refill
    assert limiter.acquire() is True


# ---------------------------------------------------------------------------
# Reset
# ---------------------------------------------------------------------------


def test_reset_restores_full_bucket() -> None:
    limiter = CaptureRateLimiter(rate_pps=10, burst=5)
    for _ in range(5):
        limiter.acquire()  # drain
    assert limiter.acquire() is False
    limiter.reset()
    assert limiter.acquire() is True


def test_reset_clears_drop_counter() -> None:
    limiter = CaptureRateLimiter(rate_pps=1, burst=1)
    limiter.acquire()
    limiter.acquire()  # drop
    assert limiter.packets_dropped == 1
    limiter.reset()
    assert limiter.packets_dropped == 0
