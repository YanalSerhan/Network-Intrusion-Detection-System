"""
Rule Engine core.

Data Setup:  Initialised with a rules directory. Starts RuleLoader.
Data Input:  ParsedPacket.
Data Output: List of Rules that matched the packet.

Matching has two modes:
  - Single-packet rules (`window: 0` or `threshold: 1`) fire immediately.
  - Aggregation rules fire once `threshold` matches occur for the same
    `group_by` value within `window` seconds, and once per episode rather than
    once per packet past the threshold. A rule with a `distinct_field` counts
    distinct values of it instead of counting matches.
"""

import logging
from typing import Any

from network_defender.parser.models import ParsedPacket
from network_defender.rules.evaluator import evaluate_condition, get_field_value
from network_defender.rules.loader import RuleLoader
from network_defender.rules.models import Rule
from network_defender.rules.window import WindowedCounter

logger = logging.getLogger(__name__)


class RuleEngine:
    """Core rule engine evaluating packets against loaded rules."""

    def __init__(self, rules_dir: str) -> None:
        """
        Initialise the engine.

        Args:
            rules_dir: Directory containing YAML rule files.
        """
        self.loader = RuleLoader(rules_dir)
        self.counter = WindowedCounter()

    def start(self) -> None:
        """Start the rule loader to monitor files."""
        self.loader.start()

    def stop(self) -> None:
        """Stop the rule loader and discard aggregation state."""
        self.loader.stop()
        self.counter.reset()

    def evaluate(self, packet: ParsedPacket) -> list[Rule]:
        """
        Evaluate a packet against all enabled rules.

        Args:
            packet: The normalised packet to test.

        Returns:
            Rules that fired for this packet. Aggregation rules are only
            included once their threshold is reached inside their window.
        """
        matched_rules = []

        for rule in self.loader.registry.get_all_enabled_rules():
            if not all(evaluate_condition(packet, condition) for condition in rule.conditions):
                continue
            if self._threshold_reached(rule, packet):
                matched_rules.append(rule)

        return matched_rules

    def _threshold_reached(self, rule: Rule, packet: ParsedPacket) -> bool:
        """
        Return True if the rule should fire for this packet.

        Single-packet rules always fire. Aggregation rules record the match and
        fire once `threshold` matches fall inside `window` seconds for the same
        `group_by` value — once per episode, not once per packet past the
        threshold, which is how one port scan came to raise eleven alerts.
        """
        if not rule.is_aggregated:
            return True

        group_value: Any = get_field_value(packet, rule.group_by)
        if group_value is None:
            # Nothing to aggregate on (e.g. group_by: src_ip on an ARP packet).
            return False

        counted = ""
        if rule.distinct_field is not None:
            distinct_value = get_field_value(packet, rule.distinct_field)
            if distinct_value is None:
                # The rule counts something this packet does not carry, so the
                # packet contributes nothing — not even a match.
                return False
            counted = str(distinct_value)

        return self.counter.fires(
            rule=rule,
            group_key=str(group_value),
            timestamp=packet.timestamp.timestamp(),
            value=counted,
        )
