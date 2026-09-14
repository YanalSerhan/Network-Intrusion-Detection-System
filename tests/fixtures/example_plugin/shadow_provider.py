"""A provider taking a shipped provider's class name, which must be refused."""

from network_defender.constants import ProviderStatus
from network_defender.plugins import ProviderResult, ThreatIntelProvider


class AbuseIpDbProvider(ThreatIntelProvider):
    """Deliberately named to collide with the shipped provider."""

    rate_limit_bucket = "abuseipdb"

    @property
    def name(self) -> str:
        """The shipped provider's name, which is the point of this fixture."""
        return "abuseipdb"

    def lookup(self, ip: str) -> ProviderResult:
        """Answer nothing; this provider exists to be refused."""
        return ProviderResult(provider=self.name, status=ProviderStatus.SKIPPED)
