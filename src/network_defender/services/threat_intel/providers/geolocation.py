"""
ip-api.com geolocation and ASN providers.

Data Setup:  Keyless; both share the 'ip_api' gatekeeper so their combined
             traffic is rate-limited as one upstream service.
Data Input:  A public IP address.
Data Output: ProviderResult carrying geolocation or ASN attribution.

Endpoint: GET http://ip-api.com/json/{ip}?fields=...
Docs:     https://ip-api.com/docs/api:json

Geolocation and ASN are separate provider classes even though one upstream
serves both. Each requests only the fields it needs, so an operator can disable
ASN attribution without losing geolocation (or swap either for a commercial
source) without touching the other. The cost is one extra request per address,
which the response cache absorbs after the first lookup.
"""

from typing import Any

from network_defender.constants import ProviderStatus

from ..base import ThreatIntelProvider
from ..http import get_json
from ..models import AsnInfo, GeoLocation, ProviderResult

IP_API_URL = "http://ip-api.com/json/{ip}"
GEO_FIELDS = "status,message,country,countryCode,regionName,city,lat,lon,timezone"
ASN_FIELDS = "status,message,as,asname,isp,org"


class _IpApiProvider(ThreatIntelProvider):
    """Shared request/validation logic for the two ip-api-backed providers."""

    fields: str = ""

    def _fetch(self, ip: str) -> dict[str, Any] | ProviderResult:
        """Request the configured fields, returning a payload or a failed result."""
        try:
            payload = self.gatekeeper.execute(
                get_json, IP_API_URL.format(ip=ip), params={"fields": self.fields}
            )
        except Exception as exc:  # noqa: BLE001 - providers must never raise
            return self._error(str(exc))

        # ip-api returns HTTP 200 with status="fail" for private or bogus input.
        if payload.get("status") != "success":
            return self._error(str(payload.get("message", "Lookup failed.")))
        return payload


class IpApiGeolocationProvider(_IpApiProvider):
    """Resolves an IP address to a country, region, city and coordinates."""

    fields = GEO_FIELDS

    @property
    def name(self) -> str:
        """Provider name; shares the 'ip_api' rate-limit bucket."""
        return "ip_api_geo"

    def lookup(self, ip: str) -> ProviderResult:
        """
        Fetch geolocation for an address.

        Args:
            ip: A public IP address.

        Returns:
            ProviderResult with `geo` populated, or status ERROR on failure.
        """
        payload = self._fetch(ip)
        if isinstance(payload, ProviderResult):
            return payload

        return ProviderResult(
            provider=self.name,
            status=ProviderStatus.OK,
            geo=GeoLocation(
                country=payload.get("country"),
                country_code=payload.get("countryCode"),
                region=payload.get("regionName"),
                city=payload.get("city"),
                latitude=payload.get("lat"),
                longitude=payload.get("lon"),
                timezone=payload.get("timezone"),
            ),
        )


class IpApiAsnProvider(_IpApiProvider):
    """Resolves an IP address to its Autonomous System and ISP."""

    fields = ASN_FIELDS

    @property
    def name(self) -> str:
        """Provider name; shares the 'ip_api' rate-limit bucket."""
        return "ip_api_asn"

    def lookup(self, ip: str) -> ProviderResult:
        """
        Fetch ASN attribution for an address.

        Args:
            ip: A public IP address.

        Returns:
            ProviderResult with `asn` populated, or status ERROR on failure.
        """
        payload = self._fetch(ip)
        if isinstance(payload, ProviderResult):
            return payload

        # ip-api returns 'as' as "AS15169 Google LLC"; keep only the identifier.
        as_field = str(payload.get("as") or "")
        asn = as_field.split(" ", 1)[0] or None

        return ProviderResult(
            provider=self.name,
            status=ProviderStatus.OK,
            asn=AsnInfo(
                asn=asn,
                organisation=payload.get("asname") or payload.get("org"),
                isp=payload.get("isp"),
            ),
        )
