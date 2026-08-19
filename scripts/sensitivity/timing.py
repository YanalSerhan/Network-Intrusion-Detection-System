"""
Capture-time helpers for the sensitivity corpus.

Data Setup:  Nothing — seeded from the constants in `pcap_scenarios.common`.
Data Input:  Scapy packets in capture order.
Data Output: The same packets, stamped with capture times.

`pcap_scenarios.at_intervals` stamps packets at a fixed step, which is right
for a fixture tuned to cross one threshold. A sensitivity corpus needs the
opposite control: the *duration* is the experimental variable, because a
detector's window is one of the two axes being swept. A scan of forty ports
over three seconds and the same forty ports over three minutes are different
findings, and only the second survives a one-second window.

`spread` draws exponential gaps rather than a fixed step with bounded jitter,
and the reason is a mistake this corpus made first. Uniform jitter of +/-15%
has a coefficient of variation of about 0.087, which is *inside* the beaconing
detector's 0.1 tolerance — so every burst in the corpus read as a beacon and
the beaconing column was measuring the fixture rather than the detector.
Exponential gaps are the standard model for packet arrivals and have a
coefficient of variation of 1.0, which is nowhere near any regularity test.
Deliberate regularity is `cadence`'s job, and only the cases that want it.
"""

import random
from typing import Any

from pcap_scenarios.common import BASE_TIME, RANDOM_SEED


def spread(packets: list[Any], seconds: float, burstiness: float = 1.0) -> list[Any]:
    """
    Stamp packets across a duration with random, bursty gaps.

    Gaps are exponentially distributed and then rescaled so the whole burst
    occupies exactly `seconds`, which keeps the duration an experimental
    variable while the arrival pattern stays realistic.

    Args:
        packets:    Packets in capture order.
        seconds:    Wall-clock span the whole burst occupies.
        burstiness: Scales the drawn gaps before rescaling. 1.0 is Poisson;
                    lower values tend toward evenly spaced. Provided so a case
                    can say it means to be regular rather than being regular
                    by accident.

    Returns:
        The same packets, with ``.time`` set.
    """
    rng = random.Random(RANDOM_SEED)
    gaps = [rng.expovariate(1.0) ** burstiness for _ in range(max(len(packets) - 1, 1))]
    scale = seconds / sum(gaps)
    now = BASE_TIME
    for index, packet in enumerate(packets):
        packet.time = now
        now += gaps[min(index, len(gaps) - 1)] * scale
    return packets


def cadence(packets: list[Any], interval: float, jitter: float = 0.0) -> list[Any]:
    """
    Stamp packets on a timer, the way a beacon or a poller behaves.

    Args:
        packets:  Packets in capture order.
        interval: Mean seconds between consecutive packets.
        jitter:   Deviation per gap, as a fraction of the interval. The
                  beaconing detector thresholds on the coefficient of
                  variation, so this is the knob that decides whether a case
                  reads as a timer or as a human.

    Returns:
        The same packets, with ``.time`` set.
    """
    rng = random.Random(RANDOM_SEED)
    now = BASE_TIME
    for packet in packets:
        packet.time = now
        now += interval * (1.0 + rng.uniform(-jitter, jitter))
    return packets
