"""Shared fixtures and builders for alert system tests."""

from datetime import UTC, datetime

import pytest

from network_defender.constants import Protocol, Severity
from network_defender.detectors.models import DetectionAlert
from network_defender.parser.models import ParsedPacket
from network_defender.rules.models import Rule, RuleCondition
from network_defender.services.alerts.models import Alert


def make_alert(
    rule_triggered: str = "TcpPortScanDetector",
    severity: Severity = Severity.HIGH,
    src_ip: str | None = "10.0.0.5",
    dst_ip: str | None = "10.0.0.9",
    timestamp: datetime | None = None,
    **overrides: object,
) -> Alert:
    """Build an Alert with sensible defaults for tests."""
    ts = timestamp or datetime.now(UTC)
    return Alert(
        timestamp=ts,
        last_seen=ts,
        severity=severity,
        rule_triggered=rule_triggered,
        src_ip=src_ip,
        dst_ip=dst_ip,
        description="test alert",
        **overrides,
    )


@pytest.fixture()
def detection() -> DetectionAlert:
    """A representative heuristic detection from the port scan detector."""
    return DetectionAlert(
        detector_name="TcpPortScanDetector",
        severity=Severity.HIGH,
        description="TCP Port Scan detected: 60 unique ports scanned.",
        src_ip="10.0.0.5",
        evidence={"unique_ports": 60},
    )


@pytest.fixture()
def packet() -> ParsedPacket:
    """A representative parsed TCP packet."""
    return ParsedPacket(
        timestamp=datetime.now(UTC),
        src_ip="10.0.0.5",
        dst_ip="10.0.0.9",
        src_port=51234,
        dst_port=443,
        protocol=Protocol.TCP,
        length=74,
        raw_summary="TCP 10.0.0.5:51234 -> 10.0.0.9:443",
    )


@pytest.fixture()
def rule() -> Rule:
    """A representative YAML-loaded rule."""
    return Rule(
        name="TCP Port Scan",
        severity=Severity.MEDIUM,
        conditions=[RuleCondition(field="protocol", operator="equals", value="tcp")],
    )
