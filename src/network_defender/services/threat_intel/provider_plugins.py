"""
Finding third-party providers, and holding them to ADR 3.

Data Setup:  Entry points and configured module paths.
Data Input:  None beyond those.
Data Output: Provider classes paired with the rate-limit bucket each asks for.

Separate from the factory because it answers a different question. The factory
asks "which providers should exist"; this asks "which providers are there to
consider", and the answer involves importing code this repository has never
seen.

The gate is `rate_limit_bucket`. A plugin names the bucket it wants, the
factory looks that bucket up in rate_limits.json, and a provider whose bucket
has no budget is not constructed. There is deliberately no way for a plugin to
supply its own gatekeeper or to go without one: ADR 3 says every outbound call
is rate-limited, and a rule a plugin can opt out of is not a rule.
"""

import inspect
import logging

from network_defender.services.threat_intel.base import ThreatIntelProvider
from network_defender.shared.extension_discovery import PROVIDER_GROUP, discover_modules

logger = logging.getLogger(__name__)


def discovered_providers(
    modules: list[str] | None = None,
    builtin_names: list[tuple[type[ThreatIntelProvider], str, str]] | None = None,
) -> list[tuple[type[ThreatIntelProvider], str, str]]:
    """
    Find plugin provider classes and the buckets they ask for.

    Args:
        modules:       Extra dotted module paths from configuration.
        builtin_names: The factory's own provider table, so a plugin cannot
                       shadow a shipped provider's name and inherit its bucket.

    Returns:
        Entries in the same shape as PROVIDER_BUCKETS. A class without a
        `rate_limit_bucket` is skipped: there is nowhere to look up its budget,
        and constructing it without one would violate ADR 3.
    """
    builtin = {entry[0].__name__ for entry in builtin_names or ()}
    found: list[tuple[type[ThreatIntelProvider], str, str]] = []
    for module in discover_modules(PROVIDER_GROUP, modules):
        for _name, obj in inspect.getmembers(module, inspect.isclass):
            if not (
                issubclass(obj, ThreatIntelProvider)
                and obj is not ThreatIntelProvider
                and not inspect.isabstract(obj)
                and obj.__name__ not in builtin
            ):
                continue
            bucket = getattr(obj, "rate_limit_bucket", None)
            if not bucket:
                logger.error(
                    "Provider %s declares no rate_limit_bucket and was not loaded; "
                    "every provider needs a gatekeeper (ADR 3).",
                    obj.__name__,
                )
                continue
            found.append((obj, getattr(obj, "config_name", obj.__name__), bucket))
    return found
