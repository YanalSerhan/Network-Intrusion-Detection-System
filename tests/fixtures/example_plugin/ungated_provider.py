"""A provider that names no rate-limit bucket, which the factory must refuse."""

from network_defender.constants import ProviderStatus
from network_defender.plugins import ProviderResult, ThreatIntelProvider


class UngatedProvider(ThreatIntelProvider):
    """Declares no bucket, so there is no budget to construct it against."""

    @property
    def name(self) -> str:
        """Unique provider name."""
        return "ungated"

    def lookup(self, ip: str) -> ProviderResult:
        """Answer nothing; this provider exists to be refused."""
        return ProviderResult(provider=self.name, status=ProviderStatus.SKIPPED)
