"""Tests for the rule snapshot repository and resynchronisation."""



from network_defender.constants import Severity
from network_defender.database.repositories import (
    RuleRepository,
)
from network_defender.rules.models import Rule, RuleCondition

# --------------------------------------------------------------------------
# Rules
# --------------------------------------------------------------------------


def _rule(name: str = "TCP Port Scan", enabled: bool = True) -> Rule:
    return Rule(
        name=name,
        severity=Severity.MEDIUM,
        enabled=enabled,
        window=60,
        threshold=15,
        conditions=[RuleCondition(field="protocol", operator="equals", value="tcp")],
    )


def test_rule_sync_and_query(rule_repo: RuleRepository) -> None:
    assert rule_repo.sync([_rule(), _rule("Disabled", enabled=False)]) == 2
    assert rule_repo.count() == 2
    assert len(rule_repo.list_rules(enabled_only=True)) == 1

    stored = rule_repo.get("TCP Port Scan")
    assert stored is not None
    assert stored.threshold == 15
    assert stored.conditions[0]["field"] == "protocol"


def test_resync_drops_rules_deleted_from_disk(rule_repo: RuleRepository) -> None:
    rule_repo.sync([_rule(), _rule("Old Rule")])
    rule_repo.sync([_rule()])

    assert rule_repo.count() == 1
    assert rule_repo.get("Old Rule") is None


def test_rule_source_paths_are_recorded_and_cleared(rule_repo: RuleRepository) -> None:
    rule_repo.sync([_rule()], {"TCP Port Scan": "rules/tcp_port_scan.yaml"})
    stored = rule_repo.get("TCP Port Scan")
    assert stored is not None and stored.source_path == "rules/tcp_port_scan.yaml"

    rule_repo.clear()
    assert rule_repo.count() == 0
