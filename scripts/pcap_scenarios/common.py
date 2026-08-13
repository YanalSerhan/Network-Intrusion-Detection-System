"""
Shared addresses, timing and constants for the synthetic traffic scenarios.

Data Setup:  Nothing — module-level constants only.
Data Input:  A list of Scapy packets in capture order.
Data Output: The same packets, stamped with plausible capture times.

Every value a scenario could otherwise hardcode lives here, so the whole
fixture set moves together when an address range or a base time changes.
"""

import random
from typing import Any

#: A routable source, so threat intel eligibility treats it as external.
ATTACKER_IP = "45.155.205.233"

#: The host under attack, on the LAN.
VICTIM_IP = "192.168.1.10"

#: A compromised internal host, used as the source for outbound scenarios.
INTERNAL_HOST_IP = "192.168.1.50"

#: An external destination in TEST-NET-3 (RFC 5737), safe to name in fixtures.
EXFIL_DESTINATION_IP = "203.0.113.77"

#: Fixed epoch seconds. A constant start time keeps generated files
#: byte-identical between runs, which is what lets them be committed.
BASE_TIME = 1_700_000_000.0

#: Fixed seed, for the same reason.
RANDOM_SEED = 20260813

#: Roughly one full-size Ethernet payload, for volume-based scenarios.
BULK_PAYLOAD = b"x" * 1400


def at_intervals(packets: list[Any], step: float = 0.01, jitter: float = 0.0) -> list[Any]:
    """
    Stamp packets with increasing capture times.

    Args:
        packets: Packets in capture order.
        step:    Seconds between consecutive packets.
        jitter:  Maximum random deviation added to each step. Non-zero jitter
                 keeps a scenario from looking like a periodic beacon to the
                 beaconing detector, which would be a false positive the
                 end-to-end assertions are meant to catch.

    Returns:
        The same packets, with ``.time`` set.
    """
    rng = random.Random(RANDOM_SEED)
    now = BASE_TIME
    for packet in packets:
        packet.time = now
        now += step + (rng.uniform(0, jitter) if jitter else 0.0)
    return packets
