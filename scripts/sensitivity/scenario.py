"""
The half-hour of traffic the alert-volume chart is drawn from.

Data Setup:  Cases from the corpus, shifted onto one shared clock.
Data Input:  None.
Data Output: Scapy packets in capture order, and where each attack sits.

The sweep replays each case in isolation, which is what makes precision and
recall well-defined. It is not what an analyst sees. This module lays the same
cases end to end with benign traffic running throughout and five attacks
placed inside it, so the different question can be asked: over half an hour,
how many alerts arrive, when, and how many of them were about anything.

The background is not filler. Every alert raised in a minute with no attack in
it is an alert someone has to read and dismiss, and that is the cost a
threshold recommendation is trading against.
"""

from typing import Any

from .case import Case
from .corpus import CORPUS

BY_NAME: dict[str, Case] = {case.name: case for case in CORPUS}

#: Benign traffic, repeated across the timeline. Each entry is a case name,
#: the offset of its first appearance, and how often it recurs.
BACKGROUND: tuple[tuple[str, float, float], ...] = (
    ("ordinary_traffic", 0.0, 100.0),
    ("availability_ping_90", 0.0, 200.0),
    ("browser_session_4ports", 30.0, 200.0),
    ("lb_backend_probe_10ports", 60.0, 300.0),
    ("resolver_busy_300q", 100.0, 600.0),
    ("config_mgmt_ssh_14", 200.0, 800.0),
    ("snmp_poll_18_hosts", 350.0, 900.0),
    ("sso_portal_18", 500.0, 600.0),
    ("telemetry_agent_60s_20", 0.0, 1800.0),
)

#: The attacks, and when each starts. Spread out so an analyst reading the
#: chart can attribute a spike to one of them rather than to their overlap.
ATTACKS: tuple[tuple[str, float], ...] = (
    ("scan_aggressive_60ports", 300.0),
    ("ssh_brute_fast_40", 620.0),
    ("syn_flood_moderate", 900.0),
    ("dns_tunnel_120q", 1150.0),
    ("lateral_smb_40", 1450.0),
)

#: Half an hour. Long enough to hold an hour-scale beacon's neighbours and a
#: five-minute evaluation interval without the chart being three bars wide.
DURATION = 1800.0

_SPANS: list[tuple[str, float, float]] = []


def _span_of(name: str) -> float:
    """Return how many seconds of capture time a case occupies."""
    times = [float(packet.time) for packet in BY_NAME[name].build()]
    return max(times) - min(times)


def _placements() -> list[tuple[str, float]]:
    """
    Return every (case, start offset) on the timeline, background first.

    A repetition that would run past the end is dropped rather than clipped.
    Half a beacon is not a quieter beacon, it is a different case, and letting
    one overrun would put alerts on the chart after the axis ends.
    """
    placed = [
        (name, first + every * index)
        for name, first, every in BACKGROUND
        for index in range(int((DURATION - first) // every) + 1)
        if first + every * index + _span_of(name) <= DURATION
    ]
    return placed + list(ATTACKS)


def compose() -> list[Any]:
    """
    Build the whole timeline as Scapy packets on one clock.

    Returns:
        Packets in capture order.
    """
    packets: list[Any] = []
    for name, offset in _placements():
        built = BY_NAME[name].build()
        base = min(float(packet.time) for packet in built)
        for packet in built:
            packet.time = offset + (float(packet.time) - base)
        packets.extend(built)
    return sorted(packets, key=lambda packet: float(packet.time))


def attack_spans() -> list[tuple[str, float, float]]:
    """
    Return each attack's name and the span of the timeline it occupies.

    Cached: building a case means building its packets, and this is asked once
    per alert raised.

    Returns:
        (case name, start, end) in seconds from the start of the timeline.
    """
    if not _SPANS:
        _SPANS.extend(
            (name, offset, offset + _span_of(name)) for name, offset in ATTACKS
        )
    return _SPANS
