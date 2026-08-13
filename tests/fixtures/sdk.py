"""
SDK instances for tests, one per lifecycle the suite needs.

Data Setup:  Each fixture builds an SDK against the per-test SQLite database
             created by the suite-wide ``isolated_database`` fixture.
Data Input:  None — the shape of the SDK is the fixture's identity.
Data Output: A NetworkDefenderSDK.

Five suites previously carried their own near-identical ``sdk`` fixture, each
free to drift from the others. Naming the variants instead makes the choice
explicit at the point of use: a test that asks for ``sdk`` is saying it wants
to drive the lifecycle itself, and one that asks for ``readonly_sdk`` is
saying it wants the SDK already up in the mode the API runs in.
"""

from collections.abc import Iterator

import pytest

from network_defender.sdk.sdk import NetworkDefenderSDK
from network_defender.shared.config_models import AppConfig, CaptureConfig, MaintenanceConfig
from network_defender.shared.rate_limit_models import RateLimitConfig, ServiceRateLimitConfig

#: An interval no test will ever wait out, so scheduled jobs only run when a
#: test drives them directly.
_NEVER_SECONDS = 3600

#: Permissive limits: enough headroom that a provider test measures the
#: provider, not the rate limiter.
_PERMISSIVE_LIMITS = ServiceRateLimitConfig(
    requests_per_minute=1000,
    requests_per_day=100_000,
    max_queue_depth=50,
    retry_attempts=0,
    retry_backoff_base_seconds=0.01,
)


def build_app_config(**overrides: object) -> AppConfig:
    """
    Build an AppConfig safe to construct an SDK from in a test.

    Capture is pointed at a nominal interface with rate limiting off, so no
    test is throttled and none of them open a real socket.

    Args:
        **overrides: Any AppConfig section to replace.

    Returns:
        A validated AppConfig.
    """
    overrides.setdefault(
        "capture", CaptureConfig(interface="eth0", max_packets_per_second=0)
    )
    return AppConfig(**overrides)


@pytest.fixture()
def sdk() -> NetworkDefenderSDK:
    """An SDK bound to the per-test database, constructed but not started."""
    return NetworkDefenderSDK(
        app_config=build_app_config(), rate_limit_config=RateLimitConfig(services={})
    )


@pytest.fixture()
def readonly_sdk() -> Iterator[NetworkDefenderSDK]:
    """An SDK already started in the read-only mode the REST API runs in."""
    instance = NetworkDefenderSDK(
        app_config=build_app_config(), rate_limit_config=RateLimitConfig(services={})
    )
    instance.start_readonly()
    try:
        yield instance
    finally:
        instance.stop_readonly()


@pytest.fixture()
def enrichment_sdk() -> NetworkDefenderSDK:
    """An SDK whose threat intel providers are configured and unthrottled."""
    return NetworkDefenderSDK(
        app_config=build_app_config(),
        rate_limit_config=RateLimitConfig(
            services={"ip_api": _PERMISSIVE_LIMITS, "whois": _PERMISSIVE_LIMITS}
        ),
    )


@pytest.fixture()
def maintenance_sdk() -> NetworkDefenderSDK:
    """An SDK whose maintenance timers never fire on their own."""
    return NetworkDefenderSDK(
        app_config=build_app_config(
            maintenance=MaintenanceConfig(
                statistics_interval_seconds=_NEVER_SECONDS,
                retention_interval_seconds=_NEVER_SECONDS,
            )
        ),
        rate_limit_config=RateLimitConfig(services={}),
    )
