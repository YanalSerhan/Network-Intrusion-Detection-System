"""Tests for which addresses may be sent to a third-party provider."""


import pytest

from network_defender.constants import ProviderStatus
from network_defender.services.threat_intel.base import ThreatIntelProvider
from network_defender.services.threat_intel.eligibility import eligible_ips, is_public_ip
from network_defender.services.threat_intel.models import (
    ProviderResult,
)
from tests.fixtures.constants import PUBLIC_IP


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
# Eligibility
# --------------------------------------------------------------------------


@pytest.mark.parametrize("ip", [PUBLIC_IP, "8.8.8.8", "2001:4860:4860::8888"])
def test_public_addresses_are_eligible(ip: str) -> None:
    assert is_public_ip(ip) is True


@pytest.mark.parametrize(
    "ip",
    [
        "10.0.0.1",
        "192.168.1.1",
        "172.16.0.1",
        "127.0.0.1",
        "169.254.1.1",
        "224.0.0.1",
        "fd00::1",
        "::1",
        "203.0.113.1",  # TEST-NET-3, reserved for documentation
        "not-an-ip",
        "",
    ],
)
def test_non_routable_and_malformed_addresses_are_refused(ip: str) -> None:
    assert is_public_ip(ip) is False


def test_eligible_ips_filters_and_deduplicates() -> None:
    assert eligible_ips("10.0.0.1", PUBLIC_IP, None, PUBLIC_IP, "8.8.8.8") == [PUBLIC_IP, "8.8.8.8"]
