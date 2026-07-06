"""Unit tests for rule discovery and hot-reloading."""

from pathlib import Path

from network_defender.constants import Severity
from network_defender.rules.loader import RuleLoader, RuleRegistry, _load_rule_file
from network_defender.rules.models import Rule, RuleCondition


def test_rule_registry_set_remove() -> None:
    registry = RuleRegistry()
    assert len(registry.get_all_enabled_rules()) == 0

    rule = Rule(
        name="Test",
        severity=Severity.LOW,
        enabled=True,
        conditions=[RuleCondition(field="proto", operator="equals", value="tcp")],
    )

    registry.set_rule("test.yaml", rule)
    assert len(registry.get_all_enabled_rules()) == 1

    registry.remove_rule("test.yaml")
    assert len(registry.get_all_enabled_rules()) == 0


def test_load_rule_file_valid(tmp_path: Path) -> None:
    registry = RuleRegistry()
    rule_file = tmp_path / "valid.yaml"
    rule_file.write_text(
        "name: Valid Rule\n"
        "severity: high\n"
        "enabled: true\n"
        "conditions:\n"
        "  - field: protocol\n"
        "    operator: equals\n"
        "    value: tcp\n"
    )

    _load_rule_file(str(rule_file), registry)
    rules = registry.get_all_enabled_rules()
    assert len(rules) == 1
    assert rules[0].name == "Valid Rule"


def test_load_rule_file_invalid_schema(tmp_path: Path) -> None:
    registry = RuleRegistry()
    rule_file = tmp_path / "invalid.yaml"
    # Missing conditions
    rule_file.write_text("name: Invalid Rule\nseverity: high\n")

    _load_rule_file(str(rule_file), registry)
    assert len(registry.get_all_enabled_rules()) == 0


def test_load_rule_file_not_dict(tmp_path: Path) -> None:
    registry = RuleRegistry()
    rule_file = tmp_path / "not_dict.yaml"
    # Just a list
    rule_file.write_text("- item 1\n- item 2\n")

    _load_rule_file(str(rule_file), registry)
    assert len(registry.get_all_enabled_rules()) == 0


def test_rule_loader_initial_load(tmp_path: Path) -> None:
    rule_file = tmp_path / "init.yaml"
    rule_file.write_text(
        "name: Init Rule\n"
        "severity: low\n"
        "enabled: true\n"
        "conditions:\n"
        "  - field: protocol\n"
        "    operator: equals\n"
        "    value: udp\n"
    )

    loader = RuleLoader(str(tmp_path))
    loader.start()
    try:
        rules = loader.registry.get_all_enabled_rules()
        assert len(rules) == 1
        assert rules[0].name == "Init Rule"
    finally:
        loader.stop()
