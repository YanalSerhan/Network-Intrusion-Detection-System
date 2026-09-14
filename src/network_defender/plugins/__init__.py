"""
The extension points, in one import.

A plugin author should not have to know that detectors live under
`detectors.base` and providers under `services.threat_intel.base`; that is
this package's internal shape, and it has changed twice. Import from here::

    from network_defender.plugins import BaseDetector, DetectorConfig

See docs/EXTENDING.md for what each contract requires.
"""

from network_defender.detectors.base import BaseDetector
from network_defender.detectors.models import DetectionAlert, DetectorConfig
from network_defender.plugins.discovery import (
    DETECTOR_GROUP,
    PROVIDER_GROUP,
    discover_modules,
)
from network_defender.services.alerts.models import Alert
from network_defender.services.alerts.notifications import NotificationHook
from network_defender.services.threat_intel.base import ThreatIntelProvider
from network_defender.services.threat_intel.models import ProviderResult

__all__ = [
    "DETECTOR_GROUP",
    "PROVIDER_GROUP",
    "Alert",
    "BaseDetector",
    "DetectionAlert",
    "DetectorConfig",
    "NotificationHook",
    "ProviderResult",
    "ThreatIntelProvider",
    "discover_modules",
]
