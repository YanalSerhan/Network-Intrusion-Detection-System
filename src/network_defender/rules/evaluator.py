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
from network_defender.rules.models import RuleCondition


def _get_field_value(packet: ParsedPacket, field_path: str) -> Any:
    """Extract a nested field value from a ParsedPacket."""
    parts = field_path.split(".")
    current: Any = packet
    for part in parts:
        if current is None:
            return None
        if hasattr(current, part):
            current = getattr(current, part)
        else:
            return None
    return current


#: Operator name from the YAML schema -> the comparison it performs. A table
#: rather than a chain of branches: adding an operator is one entry, and the
#: set of supported operators is readable in one place — which is what
#: docs/RULE_SCHEMA.md has to stay in step with.
OPERATORS: dict[str, Callable[[Any, Any], bool]] = {
    "equals": lambda field, value: bool(field == value),
    "not_equals": lambda field, value: bool(field != value),
    "greater_than": lambda field, value: bool(field > value),
    "less_than": lambda field, value: bool(field < value),
    "regex": lambda field, value: bool(re.search(str(value), str(field))),
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
