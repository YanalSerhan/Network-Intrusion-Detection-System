"""
Condition evaluation logic.

Data Setup:  No external dependencies.
Data Input:  ParsedPacket and RuleCondition.
Data Output: Boolean indicating if the packet matches the condition.
"""

import re
from collections.abc import Callable
from typing import Any

from network_defender.parser.models import ParsedPacket
from network_defender.rules.models import MAX_REGEX_SUBJECT_LENGTH, RuleCondition


def _get_field_value(packet: ParsedPacket, field_path: str) -> Any:
    """
    Extract a nested field value from a ParsedPacket.

    Private attributes are refused here as well as at rule-validation time.
    Belt and braces on purpose: this is the function that turns a string from
    a file into an attribute lookup, so it should be safe on its own terms
    rather than only because its caller checked.
    """
    current: Any = packet
    for part in field_path.split("."):
        if current is None or part.startswith("_"):
            return None
        if not hasattr(current, part):
            return None
        current = getattr(current, part)
    return current


def _search(pattern: Any, subject: Any) -> bool:
    """
    Run a regex condition, bounding the subject length.

    Catastrophic backtracking is superlinear in the length of what is being
    matched, so a cap on the subject caps what one badly-written rule can cost
    the detection thread. Every field rules match on — hostnames, paths, user
    agents — is far shorter than the cap.
    """
    return bool(re.search(str(pattern), str(subject)[:MAX_REGEX_SUBJECT_LENGTH]))


#: Operator name from the YAML schema -> the comparison it performs. A table
#: rather than a chain of branches: adding an operator is one entry, and the
#: set of supported operators is readable in one place — which is what
#: docs/RULE_SCHEMA.md has to stay in step with.
OPERATORS: dict[str, Callable[[Any, Any], bool]] = {
    "equals": lambda field, value: bool(field == value),
    "not_equals": lambda field, value: bool(field != value),
    "greater_than": lambda field, value: bool(field > value),
    "less_than": lambda field, value: bool(field < value),
    "regex": lambda field, value: _search(value, field),
}


def evaluate_condition(packet: ParsedPacket, condition: RuleCondition) -> bool:
    """Evaluate a single condition against a packet."""
    packet_value = _get_field_value(packet, condition.field)

    if packet_value is None:
        # Field missing or null (e.g., tcp_flags on a UDP packet)
        return False

    comparison = OPERATORS.get(condition.operator)
    if comparison is None:
        return False

    try:
        return comparison(packet_value, condition.value)
    except TypeError:
        # A rule can name any field and any value, so comparing a string to an
        # int is a configuration mistake rather than a bug — the rule simply
        # does not match.
        return False
