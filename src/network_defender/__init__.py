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

`__version__` is declared once, in `shared/version.py`, and everything that
reports a version derives it from there. `pyproject.toml` is the exception — a
build backend reads it before this package exists — so it carries its own copy
and a test fails if the two drift. Compare parsed versions rather than strings
when they have to agree: PEP 440 normalises the project's version string in
installed distribution metadata.
"""

from network_defender.constants import AlertSource, AlertStatus, MitreTactic, Protocol, Severity
from network_defender.detectors.base import BaseDetector
from network_defender.detectors.models import DetectionAlert, DetectorConfig
from network_defender.parser.models import ParsedPacket
from network_defender.sdk.sdk import NetworkDefenderSDK
from network_defender.services.alerts.models import Alert
from network_defender.services.alerts.notifications import NotificationHook
from network_defender.services.threat_intel.base import ThreatIntelProvider
from network_defender.shared.version import __version__

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
