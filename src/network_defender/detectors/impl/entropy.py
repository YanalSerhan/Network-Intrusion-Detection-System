"""
Shannon entropy helper.

Data Setup:  No state.
Data Input:  A string, typically a DNS query name.
Data Output: Entropy in bits per character.

Lives apart from the detectors that use it so a second detector can reach for
it without importing an unrelated module.
"""

import math
from collections import defaultdict


def shannon_entropy(value: str) -> float:
    """
    Return the Shannon entropy of a string.

    High entropy in a domain name suggests encoded or encrypted payload rather
    than a human-chosen label — the signal DNS tunnelling detection rests on.

    Args:
        value: The string to measure.

    Returns:
        Entropy in bits per character; 0.0 for an empty string.
    """
    if not value:
        return 0.0

    frequencies: defaultdict[str, int] = defaultdict(int)
    for character in value:
        frequencies[character] += 1

    entropy = 0.0
    for count in frequencies.values():
        probability = count / len(value)
        entropy -= probability * math.log2(probability)
    return entropy
