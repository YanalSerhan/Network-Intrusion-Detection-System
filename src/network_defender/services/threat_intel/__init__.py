"""
Threat Intelligence Enrichment (Milestone 8).

Enriches alerts with external context — IP reputation, geolocation, ASN and
registration data — without ever blocking detection.

Data Setup:  Providers, cache and circuit breakers injected into the service.
Data Input:  Public IP addresses taken from Alert records.
Data Output: ThreatIntelResult objects attached to those alerts.

Every outbound call routes through the ApiGatekeeper (ADR 3), responses are
TTL-cached, failing providers are cut out by a circuit breaker, and the whole
subsystem fails open: enrichment never prevents an alert from being raised.
"""

from .base import ThreatIntelProvider
from .eligibility import eligible_ips, is_public_ip
from .models import (
    AsnInfo,
    GeoLocation,
    ProviderResult,
    ThreatIntelResult,
    WhoisInfo,
)

__all__ = [
    "AsnInfo",
    "GeoLocation",
    "ProviderResult",
    "ThreatIntelProvider",
    "ThreatIntelResult",
    "WhoisInfo",
    "eligible_ips",
    "is_public_ip",
]
