"""
Condition evaluation logic.

Data Setup:  No external dependencies.
Data Input:  ParsedPacket and RuleCondition.
Data Output: Boolean indicating if the packet matches the condition.
"""

import re
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


def evaluate_condition(packet: ParsedPacket, condition: RuleCondition) -> bool:
    """Evaluate a single condition against a packet."""
    packet_value = _get_field_value(packet, condition.field)

    if packet_value is None:
        # Field missing or null (e.g., tcp_flags on a UDP packet)
        return False

    op = condition.operator
    val = condition.value

    try:
        if op == "equals":
            return bool(packet_value == val)
        if op == "not_equals":
            return bool(packet_value != val)
        if op == "greater_than":
            return bool(packet_value > val)
        if op == "less_than":
            return bool(packet_value < val)
        if op == "regex":
            return bool(re.search(str(val), str(packet_value)))
        return False
    except TypeError:
        return False
