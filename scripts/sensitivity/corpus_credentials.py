"""
Credential-guessing cases, and the automation that repeats a login honestly.

Data Setup:  Nothing.
Data Input:  None.
Data Output: Labelled cases for the two brute-force detectors.

Both detectors key on the *source*, so the negatives that matter are hosts
which legitimately authenticate over and over from one address: configuration
management opening an SSH session per managed host, and an office NAT gateway
behind which fifty people sign in to the same portal. The second is the
classic cause of a brute-force false positive in production, and no packet
field distinguishes it from one attacker working through a word list.
"""

from typing import Any

from scapy.layers.http import HTTP, HTTPRequest
from scapy.layers.inet import IP, TCP
from scapy.layers.l2 import Ether

from .case import Case, attack, benign
from .hosts import (
    ATTACKER,
    AUTOMATION_HOST,
    EDGE_SERVER,
    EPHEMERAL_BASE,
    NAT_GATEWAY,
    internal_range,
)
from .timing import spread

FAMILY = "credentials"

SSH_PORT = 22
HTTP_PORT = 80


def _ssh_attempts(src: str, targets: list[str], seconds: float) -> list[Any]:
    """One source opening an SSH connection to each target in turn."""
    return spread(
        [
            Ether()
            / IP(src=src, dst=target)
            / TCP(sport=EPHEMERAL_BASE + index, dport=SSH_PORT, flags="S")
            for index, target in enumerate(targets)
        ],
        seconds,
    )


def _auth_requests(src: str, path: bytes, count: int, seconds: float) -> list[Any]:
    """One source POSTing to an authentication endpoint repeatedly."""
    return spread(
        [
            Ether()
            / IP(src=src, dst=EDGE_SERVER)
            / TCP(sport=EPHEMERAL_BASE + index, dport=HTTP_PORT, flags="PA")
            / HTTP()
            / HTTPRequest(Method=b"POST", Path=path, Host=b"portal.example")
            for index in range(count)
        ],
        seconds,
    )


def cases() -> list[Case]:
    """Return every credential-guessing case, positive and negative."""
    return [
        attack(
            "ssh_brute_slow_8",
            {"SshBruteForceDetector"},
            lambda: _ssh_attempts(ATTACKER, [EDGE_SERVER] * 8, 180.0),
            "Eight attempts spread over three minutes — deliberately under "
            "the shipped threshold, so it is caught only by lowering it.",
            FAMILY,
        ),
        attack(
            "ssh_brute_fast_40",
            {"SshBruteForceDetector"},
            lambda: _ssh_attempts(ATTACKER, [EDGE_SERVER] * 40, 20.0),
            "A scripted password list at full speed — the loud end of the "
            "brute-force range, which any usable threshold must still catch.",
            FAMILY,
        ),
        attack(
            "http_brute_slow_12",
            {"HttpBruteForceDetector"},
            lambda: _auth_requests(ATTACKER, b"/login", 12, 180.0),
            "Twelve login POSTs over three minutes, paced to stay under the "
            "shipped threshold of twenty.",
            FAMILY,
        ),
        attack(
            "http_brute_fast_60",
            {"HttpBruteForceDetector"},
            lambda: _auth_requests(ATTACKER, b"/admin/login", 60, 30.0),
            "Sixty POSTs to an admin login in half a minute.",
            FAMILY,
        ),
        benign(
            "config_mgmt_ssh_14",
            lambda: _ssh_attempts(AUTOMATION_HOST, internal_range(14), 90.0),
            "Configuration management opening one SSH session per managed "
            "host: fourteen attempts from one source, and fourteen internal "
            "peers — a negative for two detectors at once.",
            FAMILY,
        ),
        benign(
            "ci_runner_ssh_6",
            lambda: _ssh_attempts(AUTOMATION_HOST, [EDGE_SERVER] * 6, 60.0),
            "A build runner deploying six times over a minute of work.",
            FAMILY,
        ),
        benign(
            "sso_portal_18",
            lambda: _auth_requests(NAT_GATEWAY, b"/auth/session", 18, 60.0),
            "An office behind one NAT address signing in to a portal. The "
            "textbook brute-force false positive.",
            FAMILY,
        ),
    ]
