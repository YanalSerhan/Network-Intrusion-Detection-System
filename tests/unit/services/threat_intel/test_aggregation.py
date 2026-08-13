"""Tests for combining several providers' opinions into one verdict."""


import pytest

from network_defender.constants import ProviderStatus, ThreatVerdict
from network_defender.services.threat_intel.aggregation import aggregate, classify
from network_defender.services.threat_intel.base import ThreatIntelProvider
from network_defender.services.threat_intel.models import (
    AsnInfo,
    GeoLocation,
    ProviderResult,
    WhoisInfo,
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
# Aggregation
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("score", "expected"),
    [
        (None, ThreatVerdict.UNKNOWN),
        (0.0, ThreatVerdict.CLEAN),
        (24.9, ThreatVerdict.CLEAN),
        (25.0, ThreatVerdict.SUSPICIOUS),
        (59.9, ThreatVerdict.SUSPICIOUS),
        (60.0, ThreatVerdict.MALICIOUS),
        (100.0, ThreatVerdict.MALICIOUS),
    ],
)
def test_classification_thresholds(score: float | None, expected: ThreatVerdict) -> None:
    assert classify(score) is expected


def test_aggregate_takes_the_maximum_not_the_mean() -> None:
    """One feed flagging 95 must not be diluted by three that have no opinion."""
    result = aggregate(
        PUBLIC_IP,
        [
            ProviderResult(provider="a", status=ProviderStatus.OK, reputation_score=95.0),
            ProviderResult(provider="b", status=ProviderStatus.OK, reputation_score=0.0),
            ProviderResult(provider="c", status=ProviderStatus.OK, reputation_score=0.0),
        ],
    )
    assert result.reputation_score == 95.0
    assert result.verdict is ThreatVerdict.MALICIOUS


def test_aggregate_merges_attribution_first_wins() -> None:
    result = aggregate(
        PUBLIC_IP,
        [
            ProviderResult(
                provider="a", status=ProviderStatus.OK, geo=GeoLocation(country="Russia")
            ),
            ProviderResult(
                provider="b", status=ProviderStatus.OK, geo=GeoLocation(country="Germany")
            ),
            ProviderResult(provider="c", status=ProviderStatus.OK, asn=AsnInfo(asn="AS1")),
            ProviderResult(
                provider="d", status=ProviderStatus.OK, whois=WhoisInfo(network_name="NET")
            ),
        ],
    )
    assert result.geo is not None and result.geo.country == "Russia"
    assert result.asn is not None and result.asn.asn == "AS1"
    assert result.whois is not None and result.whois.network_name == "NET"


def test_aggregate_records_failures_as_partial() -> None:
    result = aggregate(
        PUBLIC_IP,
        [
            ProviderResult(provider="ok", status=ProviderStatus.OK, reputation_score=10.0),
            ProviderResult(provider="bad", status=ProviderStatus.ERROR, error="503"),
            ProviderResult(provider="off", status=ProviderStatus.SKIPPED),
        ],
    )
    assert result.providers_queried == ["ok", "bad", "off"]
    assert result.providers_failed == ["bad", "off"]
    assert result.is_partial is True


def test_aggregate_with_no_opinions_is_unknown() -> None:
    result = aggregate(PUBLIC_IP, [ProviderResult(provider="a", status=ProviderStatus.OK)])
    assert result.verdict is ThreatVerdict.UNKNOWN
    assert result.reputation_score is None
