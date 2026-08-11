"""
AbuseIPDB reputation provider.

Data Setup:  API key read from the ABUSEIPDB_API_KEY environment variable and
             injected by the service; never a source literal.
Data Input:  A public IP address.
Data Output: ProviderResult carrying a 0-100 abuse confidence score.

Endpoint: GET https://api.abuseipdb.com/api/v2/check
Docs:     https://docs.abuseipdb.com/#check-endpoint
"""

from typing import Any

from network_defender.constants import ProviderStatus

from ..base import ThreatIntelProvider
from ..http import get_json
from ..models import ProviderResult

ABUSEIPDB_URL = "https://api.abuseipdb.com/api/v2/check"
#: Only consider reports from the last 90 days; older reports say little about
#: whether the address is hostile right now.
ABUSEIPDB_MAX_AGE_DAYS = 90


class AbuseIpDbProvider(ThreatIntelProvider):
    """Looks up an IP's abuse confidence score on AbuseIPDB."""

    requires_api_key = True

    @property
    def name(self) -> str:
        """Provider name; matches the 'abuseipdb' key in config/rate_limits.json."""
        return "abuseipdb"

    def lookup(self, ip: str) -> ProviderResult:
        """
        Fetch the abuse confidence score for an address.

        Args:
            ip: A public IP address.

        Returns:
            ProviderResult with reputation_score set, or status ERROR on failure.
        """
        if not self.is_configured:
            return ProviderResult(
                provider=self.name,
                status=ProviderStatus.SKIPPED,
                error="ABUSEIPDB_API_KEY is not set.",
            )

        try:
            payload = self.gatekeeper.execute(
                get_json,
                ABUSEIPDB_URL,
                params={"ipAddress": ip, "maxAgeInDays": ABUSEIPDB_MAX_AGE_DAYS},
                headers={"Key": self.api_key or "", "Accept": "application/json"},
            )
        except Exception as exc:  # noqa: BLE001 - providers must never raise
            return self._error(str(exc))

        return self._parse(payload)

    def _parse(self, payload: dict[str, Any]) -> ProviderResult:
        """Map an AbuseIPDB response body onto a ProviderResult."""
        data = payload.get("data")
        if not isinstance(data, dict):
            return self._error("Response contained no 'data' object.")

        score = data.get("abuseConfidenceScore")
        return ProviderResult(
            provider=self.name,
            status=ProviderStatus.OK,
            reputation_score=float(score) if isinstance(score, (int, float)) else None,
            raw={
                "total_reports": data.get("totalReports"),
                "usage_type": data.get("usageType"),
                "is_whitelisted": data.get("isWhitelisted"),
                "last_reported_at": data.get("lastReportedAt"),
                "country_code": data.get("countryCode"),
            },
        )
