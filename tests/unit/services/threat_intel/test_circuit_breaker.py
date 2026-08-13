"""Tests for the provider circuit breaker: opening, cooldown and recovery."""

import time

import pytest

from network_defender.constants import ProviderStatus
from network_defender.services.threat_intel.base import ThreatIntelProvider
from network_defender.services.threat_intel.circuit_breaker import (
    STATE_CLOSED,
    STATE_HALF_OPEN,
    STATE_OPEN,
    CircuitBreaker,
)
from network_defender.services.threat_intel.models import (
    ProviderResult,
)


class StubProvider(ThreatIntelProvider):
    """Provider double returning a scripted result and counting calls."""

    def __init__(self, name: str = "stub", result: ProviderResult | None = None) -> None:
        super().__init__(gatekeeper=None)  # type: ignore[arg-type]
        self._name = name
        self._result = result
        self.calls = 0

    @property
    def name(self) -> str:
        return self._name

    def lookup(self, ip: str) -> ProviderResult:
        self.calls += 1
        return self._result or ProviderResult(
            provider=self._name, status=ProviderStatus.OK, reputation_score=88.0
        )


# --------------------------------------------------------------------------
# Circuit breaker
# --------------------------------------------------------------------------


def test_breaker_opens_after_consecutive_failures() -> None:
    breaker = CircuitBreaker(failure_threshold=3, reset_seconds=60)
    for _ in range(2):
        breaker.record_failure()
    assert breaker.state == STATE_CLOSED

    breaker.record_failure()
    assert breaker.state == STATE_OPEN
    assert breaker.allows_request() is False


def test_success_resets_the_failure_count() -> None:
    breaker = CircuitBreaker(failure_threshold=3)
    breaker.record_failure()
    breaker.record_failure()
    breaker.record_success()
    breaker.record_failure()
    assert breaker.state == STATE_CLOSED


def test_breaker_half_opens_after_the_cooldown() -> None:
    breaker = CircuitBreaker(failure_threshold=1, reset_seconds=0.05)
    breaker.record_failure()
    assert breaker.allows_request() is False

    time.sleep(0.1)
    assert breaker.state == STATE_HALF_OPEN
    assert breaker.allows_request() is True


def test_breaker_rejects_a_non_positive_threshold() -> None:
    with pytest.raises(ValueError):
        CircuitBreaker(failure_threshold=0)
