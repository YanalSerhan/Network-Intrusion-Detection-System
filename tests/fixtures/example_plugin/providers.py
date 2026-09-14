"""
A threat intel provider written the way docs/EXTENDING.md says to write one.

`rate_limit_bucket` is the whole of the plugin contract here: it names the
budget in rate_limits.json this provider's calls come out of, and the factory
constructs the provider with the gatekeeper it finds there. A provider cannot
bring its own, which is what makes ADR 3 a property of the system rather than
a convention plugins are asked to respect.
"""

from network_defender.constants import ProviderStatus
from network_defender.plugins import ProviderResult, ThreatIntelProvider


class ExampleReputationProvider(ThreatIntelProvider):
    """An example provider that answers from a fixed table."""

    rate_limit_bucket = "abuseipdb"
    config_name = "example_reputation"

    #: Addresses this example calls bad. A real provider asks an upstream.
    KNOWN_BAD = frozenset({"198.51.100.23"})

    @property
    def name(self) -> str:
        """Unique provider name, matching its key in config/rate_limits.json."""
        return "example_reputation"

    def lookup(self, ip: str) -> ProviderResult:
        """
        Look up one address.

        Args:
            ip: A public IP address.

        Returns:
            A ProviderResult; never raises, per the base class contract.
        """
        return ProviderResult(
            provider=self.name,
            status=ProviderStatus.OK,
            reputation_score=100 if ip in self.KNOWN_BAD else 0,
        )
