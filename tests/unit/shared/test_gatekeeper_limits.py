"""
Tests that the gatekeeper's rate limits and quotas are actually enforced.

Both cases here were defects the Milestone 15 review found: a per-minute
limit that counted only successful requests, and a daily quota that was
configured, validated and reported while nothing read it.

A rate limit matters most when the system is misbehaving — during a provider
outage, when retries multiply every call — which is the condition these
tests create.
"""


import pytest

from network_defender.shared.gatekeeper import ApiGatekeeper, GatekeeperError
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


def test_failed_requests_consume_budget_too() -> None:
    """
    A request that failed still reached the provider.

    Counting only successes meant an outage fired every retry for free: with
    3 retries configured, one call became four real requests against a
    counter that never moved — and an HTTP 429 is the exact case the limit
    exists to avoid making worse.
    """
    gatekeeper = ApiGatekeeper("svc", _config(requests_per_minute=10, retry_attempts=3))

    def _always_fails() -> None:
        raise RuntimeError("provider is down")

    with pytest.raises(GatekeeperError):
        gatekeeper.execute(_always_fails)

    # One initial attempt plus three retries, all of them counted.
    assert gatekeeper.get_queue_status().requests_this_minute == 4


def test_the_daily_quota_is_enforced() -> None:
    """
    AbuseIPDB's free tier is a hard 1000/day and suspends the key past it.

    The quota was configured, validated and reported for months while nothing
    read it, so the gatekeeper would have issued fourteen times it.
    """
    gatekeeper = ApiGatekeeper("svc", _config(requests_per_minute=100, requests_per_day=3))

    for _ in range(3):
        gatekeeper.execute(lambda: "ok")

    with pytest.raises(GatekeeperError, match="Daily quota"):
        gatekeeper.execute(lambda: "ok")


def test_the_daily_quota_is_reported() -> None:
    """An operator needs to see the budget burning down before it runs out."""
    gatekeeper = ApiGatekeeper("svc", _config(requests_per_day=50))

    gatekeeper.execute(lambda: "ok")
    status = gatekeeper.get_queue_status()

    assert status.requests_today == 1
    assert status.requests_per_day_limit == 50
    assert status.seconds_until_daily_reset > 0
