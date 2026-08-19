"""
Comparing a supplied credential against the configured one.

Data Setup:  None.
Data Input:  The value a caller supplied, and the value expected.
Data Output: Whether they match.

`==` on a secret leaks its contents through timing. Python's string comparison
returns as soon as it finds a differing byte, so a caller who can measure the
response can recover a key one byte at a time — a few thousand requests, which
is nothing against an endpoint with no rate limit on failed authentication.

This is the kind of defect that is invisible in review precisely because the
wrong version looks like ordinary code.
"""

import hmac


def matches(supplied: str | None, expected: str | None) -> bool:
    """
    Return True if the supplied credential is the expected one.

    Args:
        supplied: The value from the request, or None when absent.
        expected: The configured value, or None when unset.

    Returns:
        False if either is missing; otherwise a constant-time comparison.
    """
    if supplied is None or expected is None:
        return False
    return hmac.compare_digest(supplied, expected)
