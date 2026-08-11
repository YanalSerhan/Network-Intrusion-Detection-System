"""
Which IP addresses may be sent to third-party threat intel APIs.

Data Setup:  No state; pure functions over the stdlib ipaddress module.
Data Input:  An IP address string from an Alert.
Data Output: Whether the address is eligible for external lookup.

Why this exists
---------------
Two reasons to refuse an address:

  * Privacy. Sending RFC1918 addresses to a third party leaks the shape of the
    internal network — subnet layout, host density, naming of infrastructure —
    to a vendor who has no need for it.
  * Cost. Private, loopback, link-local and reserved ranges are not routable on
    the internet, so no reputation provider has anything to say about them.
    Looking them up burns a rate-limit budget that is measured in tens of
    requests per minute.
"""

import ipaddress


def is_public_ip(ip: str) -> bool:
    """
    Return True if the address is globally routable.

    Excludes private, loopback, link-local, multicast, reserved and unspecified
    ranges for both IPv4 and IPv6. Malformed input returns False rather than
    raising, so a corrupt packet field can never break enrichment.

    Args:
        ip: The address to test.

    Returns:
        True if the address may be sent to an external provider.
    """
    try:
        address = ipaddress.ip_address(ip)
    except ValueError:
        return False

    return not (
        address.is_private
        or address.is_loopback
        or address.is_link_local
        or address.is_multicast
        or address.is_reserved
        or address.is_unspecified
    )


def eligible_ips(*candidates: str | None) -> list[str]:
    """
    Filter candidate addresses down to the public, de-duplicated ones.

    Args:
        *candidates: Address strings (or None) from an Alert.

    Returns:
        Public addresses in first-seen order, without duplicates.
    """
    seen: dict[str, None] = {}
    for candidate in candidates:
        if candidate and is_public_ip(candidate):
            seen.setdefault(candidate, None)
    return list(seen)
