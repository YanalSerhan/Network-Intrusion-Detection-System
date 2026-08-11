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

from .aggregation import aggregate, classify
from .base import ThreatIntelProvider
from .cache import ThreatIntelCache
from .circuit_breaker import CircuitBreaker
from .eligibility import eligible_ips, is_public_ip
from .factory import build_providers, build_service
from .models import (
    AsnInfo,
    GeoLocation,
    ProviderResult,
    ThreatIntelResult,
    WhoisInfo,
)
from .service import ThreatIntelService

__all__ = [
    "AsnInfo",
    "CircuitBreaker",
    "GeoLocation",
    "ProviderResult",
    "ThreatIntelProvider",
    "ThreatIntelCache",
    "ThreatIntelResult",
    "ThreatIntelService",
    "WhoisInfo",
    "aggregate",
    "build_providers",
    "build_service",
    "classify",
    "eligible_ips",
    "is_public_ip",
]
