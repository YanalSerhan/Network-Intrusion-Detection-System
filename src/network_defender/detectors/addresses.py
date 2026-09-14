"""
Address classification shared by the detectors that care where traffic went.

Data Setup:  None.
Data Input:  An address as a string, and optionally a list of IPs or CIDRs.
Data Output: Whether the address is inside the estate, and whether it is on
             an operator's list.

Two detectors need the same question answered — lateral movement asks whether
both ends are internal, exfiltration asks whether the far end is not — and it
was a private method on one of them.

Why not `ipaddress.ip_address(ip).is_internal`
---------------------------------------------
Because it answers a different question. The stdlib property means "not
globally reachable" and is true for every IANA special-purpose block: the
documentation ranges (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24), carrier
NAT space, 192.0.0.0/24, and more. An operator asking "did these bytes leave
my estate?" does not mean any of those — and the sensitivity corpus uses
documentation ranges for its external destinations precisely so that no
fixture names a real third party, so on the stdlib definition a 120 MB
transfer to an attacker never left the building.

The estate is the RFC 1918 blocks, unique-local IPv6, loopback and link-local.
Anything else is somewhere else, whether or not IANA has reserved it.
"""

import ipaddress
from collections.abc import Iterable

#: What "inside" means. RFC 1918 and its IPv6 equivalent, plus the two ranges
#: that are neither inside nor outside but are certainly not a destination
#: bytes left for: the host itself, and a link with no router on it.
INTERNAL_NETWORKS: tuple[str, ...] = (
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16",
    "fc00::/7",
    "127.0.0.0/8",
    "::1/128",
    "169.254.0.0/16",
    "fe80::/10",
)

_INTERNAL = tuple(ipaddress.ip_network(cidr) for cidr in INTERNAL_NETWORKS)


def is_internal(ip: str) -> bool:
    """
    Return True if the address belongs to the estate.

    Uses the stdlib parser rather than string prefixes: prefix matching raised
    on malformed input ("172." -> IndexError), misread addresses such as
    "172.5.0.1" as internal-adjacent, and ignored IPv6 unique-local space
    entirely even though the PRD puts IPv6 in scope.

    Args:
        ip: An address, from a packet and therefore not to be trusted.

    Returns:
        True for the networks in `INTERNAL_NETWORKS`; False for anything else,
        including unparseable input.
    """
    try:
        address = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(address in network for network in _INTERNAL if network.version == address.version)


def in_any(ip: str, networks: Iterable[str]) -> bool:
    """
    Return True if the address falls inside any of the given networks.

    Args:
        ip:       An address, from a packet and therefore not to be trusted.
        networks: Addresses or CIDR blocks, from configuration. A malformed
                  entry matches nothing rather than raising: one typo in an
                  operator's allowlist should not stop the sensor detecting.

    Returns:
        True if any network contains the address.
    """
    try:
        address = ipaddress.ip_address(ip)
    except ValueError:
        return False
    for network in networks:
        try:
            parsed = ipaddress.ip_network(network, strict=False)
        except ValueError:
            continue
        if parsed.version == address.version and address in parsed:
            return True
    return False
