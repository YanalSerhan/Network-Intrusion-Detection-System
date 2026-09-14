"""
Registered-domain extraction, for allowlisting a name and everything under it.

Data Setup:  None.
Data Input:  A DNS query name, and an operator's list of allowed domains.
Data Output: The registrable part of the name, and whether it is allowed.

Why not the public suffix list
------------------------------
Doing this exactly means shipping Mozilla's public suffix list and keeping it
current, which is a dependency and a staleness problem for one detector's
allowlist. This takes the last two labels instead, with a small table for the
suffixes where two labels is visibly wrong (`co.uk`, `com.au`, and the rest of
that shape).

The failure mode is worth stating plainly: under a multi-label suffix this
table does not know, `a.b.example.something.xy` reduces to `something.xy` and
an allowlist entry there would cover more than the operator meant. It is a
list of names they wrote down themselves, so the blast radius is bounded by
what they chose to trust — but a sensor in a country whose registry is not in
the table below should add it rather than assume.
"""

from collections.abc import Iterable

#: Two-label public suffixes common enough to be worth knowing about. Not
#: exhaustive, and deliberately not pretending to be; see the module docstring.
MULTI_LABEL_SUFFIXES = frozenset(
    {
        "ac.uk", "co.uk", "gov.uk", "ltd.uk", "me.uk", "net.uk", "org.uk", "plc.uk", "sch.uk",
        "com.au", "edu.au", "gov.au", "net.au", "org.au",
        "co.nz", "govt.nz", "net.nz", "org.nz",
        "co.jp", "ne.jp", "or.jp", "go.jp", "ac.jp",
        "co.kr", "or.kr",
        "com.br", "com.cn", "com.mx", "com.sg", "com.tr", "com.tw",
        "co.il", "co.in", "co.za",
    }
)

#: Fewest labels a name can have and still carry a registrable domain.
_MINIMUM_LABELS = 2


def registered_domain(name: str) -> str:
    """
    Return the registrable part of a hostname.

    Args:
        name: A DNS query name, with or without a trailing dot.

    Returns:
        The last two labels, or the last three when the final two are a known
        multi-label suffix. A name too short to have a registrable domain is
        returned as-is, lowercased.
    """
    labels = name.strip().rstrip(".").lower().split(".")
    if len(labels) < _MINIMUM_LABELS:
        return ".".join(labels)
    if ".".join(labels[-2:]) in MULTI_LABEL_SUFFIXES and len(labels) > _MINIMUM_LABELS:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


def is_allowlisted(name: str, allowed: Iterable[str]) -> bool:
    """
    Return True if the name's registered domain is on the allowlist.

    Matching on the registered domain rather than on the name is the point: a
    tunnel's whole technique is that every query is a different hostname, so
    an allowlist of hostnames would never match and an allowlist of suffixes
    would match anything ending in the right characters. One entry covers a
    vendor's whole domain and nothing else's.

    Args:
        name:    A DNS query name.
        allowed: Domains an operator has decided to trust.

    Returns:
        True if the name belongs to an allowed domain.
    """
    if not name:
        return False
    domain = registered_domain(name)
    return any(domain == registered_domain(entry) for entry in allowed)
