"""
A threat intel provider that lives outside this package.

ADR 3 says every outbound call goes through a gatekeeper. A plugin system is
the obvious way to lose that: hand a third party a place to put a class and
they will construct their own HTTP client. So the plugin contract is not "here
is where to register" but "name the bucket your calls come out of" — the
factory looks it up and constructs the provider with the gatekeeper it finds.

These tests are mostly about that gate, and about what happens when a plugin
does not pass it.
"""

import pytest

from network_defender.services.threat_intel.factory import build_providers
from network_defender.services.threat_intel.provider_plugins import discovered_providers
from network_defender.shared.config_models import ThreatIntelConfig

PLUGIN = "tests.fixtures.example_plugin.providers"
UNGATED = "tests.fixtures.example_plugin.ungated_provider"


def test_a_configured_module_offers_its_provider() -> None:
    found = discovered_providers([PLUGIN])
    assert [(cls.__name__, name, bucket) for cls, name, bucket in found] == [
        ("ExampleReputationProvider", "example_reputation", "abuseipdb")
    ]


def test_a_provider_without_a_bucket_is_refused(caplog: pytest.LogCaptureFixture) -> None:
    """There is nowhere to look up its budget, so there is no gatekeeper to give it."""
    assert discovered_providers([UNGATED]) == []
    assert "rate_limit_bucket" in caplog.text
    assert "ADR 3" in caplog.text


def test_a_plugin_may_not_shadow_a_shipped_provider() -> None:
    from network_defender.services.threat_intel.factory import PROVIDER_BUCKETS

    shipped = [(cls, name, bucket) for cls, name, bucket in PROVIDER_BUCKETS]
    assert discovered_providers(["tests.fixtures.example_plugin.shadow_provider"], shipped) == []


def test_a_plugin_provider_is_built_with_the_gatekeeper_for_its_bucket(
    gatekeeper: object,
) -> None:
    config = ThreatIntelConfig(
        providers=["example_reputation"], provider_modules=[PLUGIN]
    )
    providers = build_providers({"abuseipdb": gatekeeper}, config)  # type: ignore[dict-item]

    assert [p.name for p in providers] == ["example_reputation"]
    assert providers[0].gatekeeper is gatekeeper


def test_a_plugin_provider_with_no_budget_is_not_built() -> None:
    """No bucket in rate_limits.json means no gatekeeper means no provider."""
    config = ThreatIntelConfig(
        providers=["example_reputation"], provider_modules=[PLUGIN]
    )
    assert build_providers({}, config) == []


def test_a_plugin_provider_still_has_to_be_enabled() -> None:
    """Being installed is not being switched on."""
    config = ThreatIntelConfig(providers=[], provider_modules=[PLUGIN])
    assert build_providers({"abuseipdb": object()}, config) == []  # type: ignore[dict-item]
