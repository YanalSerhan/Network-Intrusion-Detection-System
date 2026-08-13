"""
Threat intel provider doubles.

Data Setup:  Nothing — the doubles hold their scripted result in memory.
Data Input:  The result a test wants the provider to return.
Data Output: A ThreatIntelProvider that never touches the network.

These bypass the gatekeeper on purpose. Aggregation, caching and circuit
breaking are the behaviour under test in the suites that use them, and a real
gatekeeper would add rate-limit timing to assertions that are not about it.
"""

from network_defender.constants import ProviderStatus
from network_defender.services.threat_intel.base import ThreatIntelProvider
from network_defender.services.threat_intel.models import ProviderResult


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


def failing_provider(name: str = "down") -> StubProvider:
    """A provider double that always reports an upstream error."""
    return StubProvider(
        name, ProviderResult(provider=name, status=ProviderStatus.ERROR, error="503")
    )
