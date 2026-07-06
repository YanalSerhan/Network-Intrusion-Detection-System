"""Unit tests for the ApiGatekeeper."""

from collections.abc import Callable
from typing import Any
from unittest.mock import MagicMock

import pytest

from network_defender.shared.gatekeeper import ApiGatekeeper, GatekeeperError
from network_defender.shared.rate_limit_models import ServiceRateLimitConfig


@pytest.fixture()
def default_config() -> ServiceRateLimitConfig:
    return ServiceRateLimitConfig(
        requests_per_minute=60,
        requests_per_day=10000,
        max_queue_depth=5,
        retry_attempts=2,
        retry_backoff_base_seconds=0.01,
    )


@pytest.fixture()
def gatekeeper(default_config: ServiceRateLimitConfig) -> ApiGatekeeper:
    return ApiGatekeeper(service_name="test_service", config=default_config)


def test_execute_success(gatekeeper: ApiGatekeeper) -> None:
    """execute() should return the api_call result on success."""
    result = gatekeeper.execute(lambda: "ok")
    assert result == "ok"


def test_execute_passes_args(gatekeeper: ApiGatekeeper) -> None:
    """execute() should forward *args and **kwargs to the api_call."""
    fn: Callable[..., Any] = lambda x, y=0: x + y  # noqa: E731
    assert gatekeeper.execute(fn, 3, y=7) == 10


def test_backpressure_rejects_when_queue_full() -> None:
    """execute() should raise GatekeeperError when the queue is at max depth."""
    cfg = ServiceRateLimitConfig(
        requests_per_minute=1,
        requests_per_day=100,
        max_queue_depth=1,
        retry_attempts=0,
        retry_backoff_base_seconds=0.01,
    )
    gk = ApiGatekeeper(service_name="svc", config=cfg)
    # Manually fill the queue to trigger backpressure.
    gk._queue.append(lambda: None)  # type: ignore[attr-defined]

    with pytest.raises(GatekeeperError, match="Queue full"):
        gk.execute(lambda: "blocked")


def test_retry_on_transient_failure(gatekeeper: ApiGatekeeper) -> None:
    """execute() should retry on exception and succeed if a later attempt passes."""
    call_count = 0

    def flaky() -> str:
        nonlocal call_count
        call_count += 1
        if call_count < 2:
            raise ConnectionError("transient")
        return "recovered"

    result = gatekeeper.execute(flaky)
    assert result == "recovered"
    assert call_count == 2


def test_all_retries_exhausted_raises(gatekeeper: ApiGatekeeper) -> None:
    """execute() should raise GatekeeperError after all retry attempts fail."""
    with pytest.raises(GatekeeperError, match="retries exhausted"):
        gatekeeper.execute(MagicMock(side_effect=ConnectionError("always fails")))


def test_get_queue_status(gatekeeper: ApiGatekeeper) -> None:
    """get_queue_status() should return a valid QueueStatus snapshot."""
    status = gatekeeper.get_queue_status()
    assert status.service_name == "test_service"
    assert status.queue_depth == 0
    assert status.is_backpressure_active is False


def test_minute_window_resets_after_60_seconds(gatekeeper: ApiGatekeeper) -> None:
    """_refresh_minute_window resets the counter when 60+ seconds have elapsed."""
    # Simulate that 61 seconds have elapsed by back-dating the window start.
    gatekeeper._requests_this_minute = 10  # type: ignore[attr-defined]
    gatekeeper._minute_window_start = gatekeeper._minute_window_start - 61  # type: ignore[attr-defined]
    gatekeeper._refresh_minute_window()  # type: ignore[attr-defined]
    assert gatekeeper._requests_this_minute == 0  # type: ignore[attr-defined]


def test_minute_window_does_not_reset_within_60_seconds(gatekeeper: ApiGatekeeper) -> None:
    """_refresh_minute_window keeps the counter intact within the window."""
    gatekeeper._requests_this_minute = 5  # type: ignore[attr-defined]
    gatekeeper._refresh_minute_window()  # type: ignore[attr-defined]
    assert gatekeeper._requests_this_minute == 5  # type: ignore[attr-defined]
