"""
Tests that a supplied credential is compared without leaking its contents.

`==` on a secret is a timing oracle. Python's string comparison returns at the
first differing byte, so a caller who can measure response time recovers the
key one byte at a time — a few thousand requests, which is nothing against an
endpoint that does not rate-limit failed authentication.

This is the kind of defect review misses because the wrong version is the one
that looks like ordinary code, so the check is here instead.
"""

import re

from network_defender.shared.credentials import matches
from network_defender.shared.paths import PROJECT_ROOT

#: Where a credential is compared. Anywhere else and the constant-time
#: guarantee is a convention rather than a fact.
API_DIR = PROJECT_ROOT / "src" / "network_defender" / "api"


def test_a_matching_credential_is_accepted() -> None:
    assert matches("s3cr3t-value", "s3cr3t-value") is True


def test_a_wrong_credential_is_rejected() -> None:
    assert matches("wrong", "s3cr3t-value") is False


def test_a_prefix_of_the_credential_is_rejected() -> None:
    """The case a timing attack builds towards, one byte at a time."""
    assert matches("s3cr3t-valu", "s3cr3t-value") is False


def test_a_missing_credential_is_rejected() -> None:
    """An absent header must not compare equal to an absent configuration."""
    assert matches(None, "s3cr3t-value") is False
    assert matches("anything", None) is False
    assert matches(None, None) is False


def test_no_route_compares_a_credential_with_an_operator() -> None:
    """
    The comparison has to go through `credentials.matches`.

    Both call sites used `==` and `!=` until this milestone. Nothing failed,
    because a timing side channel does not show up in a functional test —
    which is exactly why it needs a structural one.
    """
    suspicious = re.compile(r"(expected|api_key|token|secret)\s*(==|!=)")
    offenders = [
        path.relative_to(PROJECT_ROOT)
        for path in sorted(API_DIR.rglob("*.py"))
        if suspicious.search(path.read_text())
    ]

    assert not offenders, (
        f"{offenders} compare a credential with an operator. Use "
        f"shared.credentials.matches, which is constant-time."
    )
