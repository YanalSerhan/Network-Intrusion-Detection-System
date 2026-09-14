"""
Rule Engine module.

Provides a declarative YAML-based rule evaluation engine for network packets.
"""

from network_defender.rules.engine import RuleEngine
from network_defender.rules.evaluator import evaluate_condition
from network_defender.rules.loader import RuleLoader, RuleRegistry
from network_defender.rules.models import Rule, RuleCondition

__all__ = [
    "RuleEngine",
    "RuleLoader",
    "RuleRegistry",
    "Rule",
    "RuleCondition",
    "evaluate_condition",
]
