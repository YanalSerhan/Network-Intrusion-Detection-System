"""
What one sample in the sensitivity corpus is.

Data Setup:  Nothing — a case is a builder plus a label.
Data Input:  None.
Data Output: A `Case`.

The corpus is a labelled classification problem, not a fixture set. Each case
is one host behaving one way for a bounded period, and its label records which
detectors *ought* to fire on it. A case labelled with no detectors is not
filler: it is the only reason a false positive can be counted at all, and
without enough of those every precision figure would be 1.0 by construction.

Labels are deliberately per-detector rather than a single "malicious" bit. A
SYN flood is malicious and is not a port scan, so the flood case is a positive
sample for `SynFloodDetector` and a *negative* sample for `TcpPortScanDetector`
— firing on it is a false positive, however malicious the traffic is.
"""

from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

#: A builder returns Scapy packets already stamped with capture times.
Builder = Callable[[], list[Any]]


@dataclass(frozen=True)
class Case:
    """One labelled traffic sample."""

    #: Stable identifier, used as the row key in every results file.
    name: str

    #: Detector class names that should fire on this case. Empty for traffic
    #: that is either benign or malicious-but-not-this-detector's-business.
    expected: frozenset[str]

    #: Builds the packets. Called once; the result is parsed and cached.
    build: Builder

    #: Why this case is in the corpus — in particular, for a negative case,
    #: which detector it is trying to fool and how.
    note: str

    #: Free-form grouping for reporting: "recon", "flood", "c2", and so on.
    family: str = field(default="misc")

    @property
    def is_positive(self) -> bool:
        """Return True when at least one detector is expected to fire."""
        return bool(self.expected)


def attack(name: str, expected: set[str], build: Builder, note: str, family: str) -> Case:
    """
    Build a positive case.

    Args:
        name:     Stable identifier.
        expected: Detector class names that should fire.
        build:    Packet builder.
        note:     Why the case is in the corpus.
        family:   Reporting group.

    Returns:
        The case.
    """
    return Case(name=name, expected=frozenset(expected), build=build, note=note, family=family)


def benign(name: str, build: Builder, note: str, family: str) -> Case:
    """
    Build a negative case — traffic no detector should report.

    Args:
        name:   Stable identifier.
        build:  Packet builder.
        note:   Which detector this case is trying to fool, and how.
        family: Reporting group.

    Returns:
        The case.
    """
    return Case(name=name, expected=frozenset(), build=build, note=note, family=family)
