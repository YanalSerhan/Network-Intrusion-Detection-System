"""Unit tests for rule engine models."""

import pytest
from pydantic import ValidationError

from network_defender.constants import Severity
from network_defender.rules.models import Rule, RuleCondition


def test_rule_condition_valid() -> None:
    cond = RuleCondition(field="protocol", operator="equals", value="tcp")
    assert cond.field == "protocol"
    assert cond.operator == "equals"
    assert cond.value == "tcp"


def test_rule_valid() -> None:
    rule = Rule(
        name="Test Rule",
        severity=Severity.HIGH,
        enabled=True,
        conditions=[RuleCondition(field="protocol", operator="equals", value="tcp")],
    )
    assert rule.name == "Test Rule"
    assert rule.severity == Severity.HIGH
    assert rule.enabled is True
    assert rule.window == 0


def test_rule_invalid_empty_conditions() -> None:
    with pytest.raises(ValidationError):
        Rule(
            name="Test Rule",
            severity=Severity.HIGH,
            conditions=[],  # min_length=1
        )
