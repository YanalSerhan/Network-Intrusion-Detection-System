"""
Network Defender — the public package surface.

Everything here is API: named in `__all__`, documented, and not renamed
without a version bump. Everything else is internal, whatever its import path
looks like, and the split matters because the two have different obligations —
one is a promise to people who are not in this repository.

Three groups, because consumers arrive for three different reasons.

**Run it.** `NetworkDefenderSDK` is the only entry point. The CLI and the REST
API are both built on it and reach past it for nothing, which is what keeps
the two from drifting into disagreeing about what "start" means::

    from network_defender import NetworkDefenderSDK

    sdk = NetworkDefenderSDK.create()
    sdk.start_offline()
    sdk.start_capture_from_pcap(Path("capture.pcap"))
    for alert in sdk.list_alerts():
        ...

**Read what it produces.** `Alert` is what the SDK returns, and `Severity`,
`AlertStatus`, `AlertSource`, `MitreTactic` and `Protocol` are the enumerations
its fields hold. Without these a consumer compares against string literals,
which is how a renamed member becomes a silent behaviour change downstream.

**Extend it.** `BaseDetector` and `DetectorConfig` add a detector,
`ThreatIntelProvider` adds an enrichment source, and `NotificationHook` adds a
channel for alerts to leave by. `DetectionAlert` is what a detector emits and
`ParsedPacket` is what it is given. See docs/EXTENDING.md.

`__version__` is the one in `pyproject.toml`; note that PEP 440 normalises the
project's `1.00` to `1.0` in installed distribution metadata, so compare
parsed versions rather than strings if the two ever have to agree.
"""

from .constants import AlertSource, AlertStatus, MitreTactic, Protocol, Severity
from .detectors.base import BaseDetector
from .detectors.models import DetectionAlert, DetectorConfig
from .parser.models import ParsedPacket
from .sdk.sdk import NetworkDefenderSDK
from .services.alerts.models import Alert
from .services.alerts.notifications import NotificationHook
from .services.threat_intel.base import ThreatIntelProvider
from .shared.version import __version__

__all__ = [
    # Run it.
    "NetworkDefenderSDK",
    # Read what it produces.
    "Alert",
    "AlertSource",
    "AlertStatus",
    "MitreTactic",
    "Protocol",
    "Severity",
    # Extend it.
    "BaseDetector",
    "DetectionAlert",
    "DetectorConfig",
    "NotificationHook",
    "ParsedPacket",
    "ThreatIntelProvider",
    # What version of all of the above this is.
    "__version__",
]
