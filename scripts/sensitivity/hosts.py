"""
The addresses the sensitivity corpus uses.

Data Setup:  Module-level constants only.
Data Input:  None.
Data Output: Addresses and small helpers for building them.

Kept apart from `pcap_scenarios.common` because the corpus needs a wider cast:
benign cases have to come from somewhere that is plausibly *not* an attacker,
and the lateral-movement and flood cases need populations of hosts rather than
the single attacker/victim pair the golden fixtures use.

Every external address is from a range reserved for documentation (RFC 5737)
or is a well-known public resolver, so nothing here names a real third party.
"""

#: An external attacker, outside any private range.
ATTACKER = "198.51.100.23"

#: The externally-reachable server most inbound cases target.
EDGE_SERVER = "192.168.1.10"

#: A compromised internal workstation — the source for outbound attack cases.
COMPROMISED_HOST = "192.168.1.50"

#: An ordinary internal workstation, the source for most benign cases.
WORKSTATION = "192.168.1.60"

#: Internal infrastructure whose *job* is to talk to everything. These are the
#: hosts that make the benign cases hard: a monitoring server's traffic is
#: shaped exactly like reconnaissance, and telling them apart is the whole
#: problem this corpus measures.
MONITOR = "192.168.1.20"
BACKUP_SERVER = "192.168.1.21"
LOAD_BALANCER = "192.168.1.22"
AUTOMATION_HOST = "192.168.1.23"
NAT_GATEWAY = "192.168.1.24"

#: External destinations for outbound cases.
C2_SERVER = "203.0.113.77"
CLOUD_STORAGE = "203.0.113.90"
NTP_SERVER = "203.0.113.123"
PUBLIC_RESOLVER = "8.8.8.8"

#: Ephemeral source ports start here; cases add an index so every connection
#: is distinct, which is what makes a burst read as many connections rather
#: than one long-lived session.
EPHEMERAL_BASE = 40000


def internal_range(count: int, start: int = 100) -> list[str]:
    """
    Return a block of internal addresses.

    Args:
        count: How many addresses.
        start: Final octet of the first address.

    Returns:
        Addresses in 192.168.1.0/24, one per host.
    """
    return [f"192.168.1.{start + offset}" for offset in range(count)]


def client_range(count: int) -> list[str]:
    """
    Return a block of distinct external client addresses.

    Used by the busy-server cases, where the point is that many *different*
    clients reach one destination — the shape a flood detector keying on the
    destination cannot distinguish from an attack.

    Args:
        count: How many clients.

    Returns:
        Addresses in 203.0.113.0/24 (RFC 5737 TEST-NET-3).
    """
    return [f"203.0.113.{1 + offset % 254}" for offset in range(count)]
