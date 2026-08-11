"""
ThreatIntelProvider — the extension point for pluggable enrichment sources.

Data Setup:  Each provider receives its ApiGatekeeper (and any API key) via
             __init__. Providers never construct their own HTTP policy.
Data Input:  A single public IP address string.
Data Output: A ProviderResult, including on failure.

Contract for implementors
-------------------------
  * `lookup()` must never raise. Return a ProviderResult with status ERROR
    instead — the system fails open and keeps alerting without enrichment.
  * Every outbound request must go through `self.gatekeeper.execute(...)`.
    Direct HTTP calls bypass rate limiting and are a violation of ADR 3.
  * `requires_api_key` lets the service skip a provider that is not configured
    rather than burning retries on guaranteed 401s.
"""

from abc import ABC, abstractmethod

from network_defender.shared.base import LoggableMixin
from network_defender.shared.gatekeeper import ApiGatekeeper

from .models import ProviderResult


class ThreatIntelProvider(LoggableMixin, ABC):
    """Abstract base class for all threat intelligence providers."""

    #: Set True by providers that cannot function without a configured key.
    requires_api_key: bool = False

    def __init__(self, gatekeeper: ApiGatekeeper, api_key: str | None = None) -> None:
        """
        Initialise the provider.

        Args:
            gatekeeper: Gatekeeper enforcing rate limits for this provider's service.
            api_key:    Credential loaded from the environment; never a literal.
        """
        self.gatekeeper = gatekeeper
        self.api_key = api_key

    @property
    @abstractmethod
    def name(self) -> str:
        """Unique provider name, matching its key in config/rate_limits.json."""

    @property
    def is_configured(self) -> bool:
        """True if this provider has everything it needs to run."""
        return bool(self.api_key) if self.requires_api_key else True

    @abstractmethod
    def lookup(self, ip: str) -> ProviderResult:
        """
        Look up a single IP address.

        Args:
            ip: A public IP address.

        Returns:
            A ProviderResult. Implementations must not raise; failures are
            reported as ProviderResult(status=ERROR).
        """

    def _error(self, message: str) -> ProviderResult:
        """Build a failed ProviderResult for this provider."""
        from network_defender.constants import ProviderStatus

        return ProviderResult(provider=self.name, status=ProviderStatus.ERROR, error=message)
