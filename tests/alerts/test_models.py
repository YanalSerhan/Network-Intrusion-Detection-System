"""Unit tests for the Alert model and severity handling."""

from uuid import UUID

import pytest
from pydantic import ValidationError

from network_defender.constants import (
    SEVERITY_ORDER,
    AlertSource,
    AlertStatus,
    MitreTactic,
    Severity,
)
from network_defender.services.alerts.models import Alert

from .conftest import make_alert


def test_alert_gets_unique_uuid_and_utc_timestamp() -> None:
    first, second = make_alert(), make_alert()
    assert isinstance(first.alert_id, UUID)
    assert first.alert_id != second.alert_id
    assert first.timestamp.tzinfo is not None


def test_alert_defaults() -> None:
    alert = make_alert()
    assert alert.status is AlertStatus.NEW
    assert alert.source is AlertSource.DETECTOR
    assert alert.occurrences == 1
    assert alert.confidence == 0.0
    assert alert.evidence == {}


def test_severity_enum_covers_all_five_levels() -> None:
    assert [s.value for s in Severity] == ["info", "low", "medium", "high", "critical"]
    assert SEVERITY_ORDER[Severity.CRITICAL] > SEVERITY_ORDER[Severity.INFO]
    assert sorted(SEVERITY_ORDER.values()) == [0, 1, 2, 3, 4]


def test_alert_accepts_full_payload() -> None:
    alert = make_alert(
        severity=Severity.CRITICAL,
        confidence=0.91,
        tactic=MitreTactic.EXFILTRATION,
        technique="T1041",
        src_port=1234,
        dst_port=53,
        protocol="udp",
        packet_summary="UDP 10.0.0.5:1234 -> 10.0.0.9:53",
        evidence={"bytes_out": 5_000_000},
    )
    assert alert.tactic is MitreTactic.EXFILTRATION
    assert alert.evidence["bytes_out"] == 5_000_000


@pytest.mark.parametrize("confidence", [-0.1, 1.1])
def test_confidence_must_be_a_probability(confidence: float) -> None:
    with pytest.raises(ValidationError):
        make_alert(confidence=confidence)


def test_port_range_is_validated() -> None:
    with pytest.raises(ValidationError):
        make_alert(dst_port=70000)


def test_occurrences_must_be_positive() -> None:
    with pytest.raises(ValidationError):
        make_alert(occurrences=0)


def test_severity_is_required() -> None:
    with pytest.raises(ValidationError):
        Alert(rule_triggered="X", description="d")  # type: ignore[call-arg]


def test_dedup_key_groups_identical_events() -> None:
    assert make_alert().dedup_key() == make_alert().dedup_key()
    assert make_alert().dedup_key() != make_alert(src_ip="10.0.0.6").dedup_key()
    assert make_alert().dedup_key() != make_alert(severity=Severity.LOW).dedup_key()


def test_dedup_key_tolerates_missing_ips() -> None:
    assert make_alert(src_ip=None, dst_ip=None).dedup_key() == (
        "TcpPortScanDetector",
        "",
        "",
        "high",
    )
