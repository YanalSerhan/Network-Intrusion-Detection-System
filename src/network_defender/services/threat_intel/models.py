"""
Pydantic models for threat intelligence enrichment.

Data Setup:  No external dependencies; built from provider API responses.
Data Input:  Normalised fields parsed by each provider adapter.
Data Output: Enrichment records attached to Alerts and cached by the TI service.
"""

from datetime import UTC, datetime
from typing import Any

from pydantic import BaseModel, Field

from network_defender.constants import (
    REPUTATION_MAX,
    REPUTATION_MIN,
    ProviderStatus,
    ThreatVerdict,
)


class GeoLocation(BaseModel):
    """Geographic attribution for an IP address."""

    country: str | None = Field(default=None, description="Country name.")
    country_code: str | None = Field(default=None, description="ISO 3166-1 alpha-2 code.")
    region: str | None = Field(default=None, description="Region or state name.")
    city: str | None = Field(default=None, description="City name.")
    latitude: float | None = Field(default=None, ge=-90, le=90, description="Latitude.")
    longitude: float | None = Field(default=None, ge=-180, le=180, description="Longitude.")
    timezone: str | None = Field(default=None, description="IANA timezone name.")


class AsnInfo(BaseModel):
    """Autonomous System attribution for an IP address."""

    asn: str | None = Field(default=None, description="AS number (e.g. 'AS15169').")
    organisation: str | None = Field(default=None, description="AS organisation name.")
    isp: str | None = Field(default=None, description="Internet service provider name.")


class WhoisInfo(BaseModel):
    """Registration data for the network block containing an IP address."""

    network_name: str | None = Field(default=None, description="Registered network name.")
    cidr: str | None = Field(default=None, description="Allocated CIDR block.")
    registry: str | None = Field(default=None, description="Regional registry (ARIN, RIPE, …).")
    registrant: str | None = Field(default=None, description="Registrant organisation.")
    abuse_email: str | None = Field(default=None, description="Abuse contact address.")
    registered_on: str | None = Field(default=None, description="Registration date (ISO 8601).")


class ProviderResult(BaseModel):
    """
    The outcome of a single provider lookup.

    A failed lookup is a first-class result rather than an exception: the PRD
    requires the system to fail open and keep alerting without enrichment.
    """

    provider: str = Field(description="Name of the provider that produced this result.")
    status: ProviderStatus = Field(description="Whether the lookup succeeded, failed or skipped.")
    reputation_score: float | None = Field(
        default=None,
        ge=REPUTATION_MIN,
        le=REPUTATION_MAX,
        description="Maliciousness score in [0, 100]; None if the provider reports no opinion.",
    )
    geo: GeoLocation | None = Field(default=None, description="Geolocation, when provided.")
    asn: AsnInfo | None = Field(default=None, description="ASN attribution, when provided.")
    whois: WhoisInfo | None = Field(default=None, description="Registration data, when provided.")
    error: str | None = Field(default=None, description="Failure reason when status is 'error'.")
    raw: dict[str, Any] = Field(
        default_factory=dict, description="Selected raw fields retained for analyst drill-down."
    )

    @property
    def succeeded(self) -> bool:
        """True if the provider returned usable data."""
        return self.status is ProviderStatus.OK


class ThreatIntelResult(BaseModel):
    """Aggregated enrichment for a single IP address, attached to an Alert."""

    ip: str = Field(description="The IP address that was enriched.")
    verdict: ThreatVerdict = Field(
        default=ThreatVerdict.UNKNOWN, description="Aggregated reputation verdict."
    )
    reputation_score: float | None = Field(
        default=None,
        ge=REPUTATION_MIN,
        le=REPUTATION_MAX,
        description="Aggregated maliciousness score in [0, 100].",
    )
    geo: GeoLocation | None = Field(default=None, description="Merged geolocation.")
    asn: AsnInfo | None = Field(default=None, description="Merged ASN attribution.")
    whois: WhoisInfo | None = Field(default=None, description="Merged registration data.")
    providers_queried: list[str] = Field(
        default_factory=list, description="Providers consulted for this lookup."
    )
    providers_failed: list[str] = Field(
        default_factory=list, description="Providers that errored or were skipped."
    )
    enriched_at: datetime = Field(
        default_factory=lambda: datetime.now(UTC), description="Enrichment time (UTC)."
    )

    @property
    def is_partial(self) -> bool:
        """True if at least one provider failed, so the picture is incomplete."""
        return bool(self.providers_failed)
