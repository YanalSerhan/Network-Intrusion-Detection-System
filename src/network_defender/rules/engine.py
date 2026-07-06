"""
Rule Engine core.

Data Setup:  Initialised with a rules directory. Starts RuleLoader.
Data Input:  ParsedPacket.
Data Output: List of Rules that matched the packet.
"""

import logging

from network_defender.parser.models import ParsedPacket
from network_defender.rules.evaluator import evaluate_condition
from network_defender.rules.loader import RuleLoader
from network_defender.rules.models import Rule

logger = logging.getLogger(__name__)


class RuleEngine:
    """Core rule engine evaluating packets against loaded rules."""

    def __init__(self, rules_dir: str) -> None:
        self.loader = RuleLoader(rules_dir)

    def start(self) -> None:
        """Start the rule loader to monitor files."""
        self.loader.start()

    def stop(self) -> None:
        """Stop the rule loader."""
        self.loader.stop()

    def evaluate(self, packet: ParsedPacket) -> list[Rule]:
        """
        Evaluate a packet against all enabled rules.

        Returns a list of Rule objects that completely matched the packet.
        """
        matched_rules = []
        rules = self.loader.registry.get_all_enabled_rules()

        for rule in rules:
            matches = True
            for condition in rule.conditions:
                if not evaluate_condition(packet, condition):
                    matches = False
                    break

            if matches:
                matched_rules.append(rule)

        return matched_rules
