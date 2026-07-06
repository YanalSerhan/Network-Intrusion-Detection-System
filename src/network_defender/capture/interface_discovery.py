"""
Network interface discovery utilities.

Data Setup:  No external dependencies; wraps Scapy's interface enumeration.
Data Input:  Host OS network interface list (via Scapy).
Data Output: Sorted list of interface name strings; best-candidate interface name.
"""

import re

from scapy.arch import get_if_list  # type: ignore[import-untyped]

# Patterns for interfaces we consider "virtual" or "loopback" and skip during auto-select.
_LOOPBACK_PATTERN = re.compile(r"^(lo|lo\d+|loopback)", re.IGNORECASE)
_VIRTUAL_PATTERN = re.compile(r"^(docker|virbr|veth|vmnet|br-|tun|tap)", re.IGNORECASE)


def list_interfaces() -> list[str]:
    """
    Return a sorted list of all network interface names visible to Scapy.

    Returns:
        Sorted list of interface name strings (e.g. ['eth0', 'lo', 'wlan0']).
    """
    return sorted(get_if_list())


def is_loopback(interface: str) -> bool:
    """
    Return True if the interface name looks like a loopback adapter.

    Args:
        interface: Interface name to evaluate.

    Returns:
        True if the interface matches a known loopback pattern.
    """
    return bool(_LOOPBACK_PATTERN.match(interface))


def is_virtual(interface: str) -> bool:
    """
    Return True if the interface name looks like a virtual/bridge adapter.

    Args:
        interface: Interface name to evaluate.

    Returns:
        True if the interface matches a known virtual-interface pattern.
    """
    return bool(_VIRTUAL_PATTERN.match(interface))


def auto_select_interface() -> str:
    """
    Return the best candidate physical interface for packet capture.

    Selection algorithm:
      1. Filter out loopback and known virtual interfaces.
      2. Return the lexicographically first remaining interface.
      3. If none survive, fall back to the first interface overall.

    Returns:
        Interface name string.

    Raises:
        RuntimeError: If no network interfaces are visible at all.
    """
    all_ifaces = list_interfaces()
    if not all_ifaces:
        raise RuntimeError(
            "No network interfaces found. Ensure Scapy has the required privileges."
        )

    candidates = [i for i in all_ifaces if not is_loopback(i) and not is_virtual(i)]
    if candidates:
        return candidates[0]

    # Fallback: return first interface even if it's loopback
    return all_ifaces[0]
