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

from network_defender.services.threat_intel.aggregation import aggregate, classify
from network_defender.services.threat_intel.base import ThreatIntelProvider
from network_defender.services.threat_intel.cache import ThreatIntelCache
from network_defender.services.threat_intel.circuit_breaker import CircuitBreaker
from network_defender.services.threat_intel.eligibility import eligible_ips, is_public_ip
from network_defender.services.threat_intel.factory import build_providers, build_service
from network_defender.services.threat_intel.models import (
    AsnInfo,
    GeoLocation,
    ProviderResult,
    ThreatIntelResult,
    WhoisInfo,
)
from network_defender.services.threat_intel.service import ThreatIntelService

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
