"""
Threat intel provider implementations.

Each module here adapts one upstream service to the ThreatIntelProvider port.
Adding a provider requires no changes to the service: subclass the port, add a
rate-limit entry in config/rate_limits.json, and register it.
"""

from network_defender.services.threat_intel.providers.geolocation import (
    IpApiAsnProvider,
    IpApiGeolocationProvider,
)
from network_defender.services.threat_intel.providers.reputation import AbuseIpDbProvider
from network_defender.services.threat_intel.providers.whois import RdapWhoisProvider

__all__ = [
    "AbuseIpDbProvider",
    "IpApiAsnProvider",
    "IpApiGeolocationProvider",
    "RdapWhoisProvider",
]
