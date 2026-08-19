"""
Timer-driven cases: malware calling home, and software that also runs on one.

Data Setup:  Nothing.
Data Input:  None.
Data Output: Labelled cases for the beaconing detector.

Regularity is the whole signal, and the awkward fact this corpus records is
that a great deal of legitimate software is regular: telemetry agents post on
a fixed schedule, health checks poll on one, and neither jitters. The
detector's only defence is the interval-variance tolerance, and these cases
are what measure whether that defence does any work.

Note the interaction with the window axis. Timestamps are cleared on every
evaluation, so a beacon is only visible when the window is long enough to hold
`connection_count_threshold` of its intervals — which for a sixty-second
beacon means a window ten minutes long.
"""

from typing import Any

from scapy.layers.inet import IP, TCP
from scapy.layers.l2 import Ether

from .case import Case, attack, benign
from .hosts import (
    C2_SERVER,
    CLOUD_STORAGE,
    COMPROMISED_HOST,
    EDGE_SERVER,
    MONITOR,
    WORKSTATION,
)
from .timing import cadence

FAMILY = "beaconing"

#: Every case here runs over TLS, which is what both malware and telemetry
#: agents use. The detector does not look at the port, so varying it would
#: only add a column nothing reads.
HTTPS_PORT = 443


def _timer(src: str, dst: str, count: int, interval: float, jitter: float = 0.0) -> list[Any]:
    """One source contacting one destination on a schedule."""
    return cadence(
        [Ether() / IP(src=src, dst=dst) / TCP(dport=HTTPS_PORT, flags="S") for _ in range(count)],
        interval,
        jitter,
    )


def cases() -> list[Case]:
    """Return every timer-driven case, positive and negative."""
    return [
        attack(
            "beacon_5s_30",
            {"BeaconingDetector"},
            lambda: _timer(COMPROMISED_HOST, C2_SERVER, 30, 5.0),
            "A fast beacon: thirty check-ins five seconds apart. The only "
            "positive short enough for a short window to accumulate.",
            FAMILY,
        ),
        attack(
            "beacon_30s_18_jittered",
            {"BeaconingDetector"},
            lambda: _timer(COMPROMISED_HOST, C2_SERVER, 18, 30.0, 0.06),
            "A beacon with light jitter, still inside the variance tolerance "
            "— malware adding a little noise to evade exactly this detector.",
            FAMILY,
        ),
        attack(
            "beacon_60s_20",
            {"BeaconingDetector"},
            lambda: _timer(COMPROMISED_HOST, C2_SERVER, 20, 60.0),
            "A one-minute beacon over twenty minutes: the interval the "
            "shipped hour-long window was chosen for.",
            FAMILY,
        ),
        benign(
            "telemetry_agent_60s_20",
            lambda: _timer(WORKSTATION, CLOUD_STORAGE, 20, 60.0),
            "A telemetry agent posting once a minute, exactly on the timer. "
            "Identical in shape to the sixty-second beacon above; only the "
            "destination differs, and the detector does not look at that.",
            FAMILY,
        ),
        benign(
            "healthcheck_poll_10s_40",
            lambda: _timer(MONITOR, EDGE_SERVER, 40, 10.0),
            "A health check every ten seconds — regular, frequent, and the "
            "negative that a short window is most likely to report.",
            FAMILY,
        ),
        benign(
            "human_browsing_burst",
            lambda: _timer(WORKSTATION, CLOUD_STORAGE, 24, 9.0, 0.85),
            "A person reading pages: the same volume as a beacon with none of "
            "the regularity. A control for the variance test itself.",
            FAMILY,
        ),
    ]
