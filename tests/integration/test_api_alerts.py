"""API tests for listing, filtering and paginating alerts."""

from datetime import UTC, datetime, timedelta

from fastapi.testclient import TestClient

from network_defender.constants import Severity
from network_defender.sdk.sdk import NetworkDefenderSDK
from network_defender.services.alerts.models import Alert

ALERTS = "/api/v1/alerts"
def _seed(readonly_sdk: NetworkDefenderSDK, count: int, severity: Severity = Severity.HIGH) -> None:
    now = datetime.now(UTC)
    for index in range(count):
        stamp = now + timedelta(seconds=index)
        readonly_sdk._alert_service.repository.save(
            Alert(
                timestamp=stamp,
                last_seen=stamp,
                severity=severity,
                rule_triggered=f"Rule{index}",
                src_ip=f"10.0.0.{index}",
                description="seeded",
            )
        )


# --------------------------------------------------------------------------
# Listing
# --------------------------------------------------------------------------


def test_list_alerts_returns_a_page_envelope(client: TestClient, seeded_alert: Alert) -> None:
    response = client.get(ALERTS)
    assert response.status_code == 200

    body = response.json()
    assert len(body["items"]) == 1
    assert body["items"][0]["rule_triggered"] == "TcpPortScanDetector"
    assert body["meta"]["count"] == 1
    assert body["meta"]["has_more"] is False


def test_list_alerts_is_empty_before_anything_happens(client: TestClient) -> None:
    body = client.get(ALERTS).json()
    assert body["items"] == []
    assert body["meta"]["count"] == 0


def test_list_alerts_returns_newest_first(
    client: TestClient,
    readonly_sdk: NetworkDefenderSDK,
) -> None:
    _seed(readonly_sdk, 3)
    names = [item["rule_triggered"] for item in client.get(ALERTS).json()["items"]]
    assert names == ["Rule2", "Rule1", "Rule0"]


def test_list_alerts_filters_by_severity(
    client: TestClient,
    readonly_sdk: NetworkDefenderSDK,
) -> None:
    _seed(readonly_sdk, 2, severity=Severity.HIGH)
    _seed(readonly_sdk, 1, severity=Severity.LOW)

    assert len(client.get(ALERTS, params={"severity": "low"}).json()["items"]) == 1
    assert len(client.get(ALERTS, params={"severity": "critical"}).json()["items"]) == 0


def test_list_alerts_filters_by_status(client: TestClient, seeded_alert: Alert) -> None:
    assert len(client.get(ALERTS, params={"status": "new"}).json()["items"]) == 1
    assert len(client.get(ALERTS, params={"status": "resolved"}).json()["items"]) == 0


def test_list_alerts_filters_by_time_window(
    client: TestClient, readonly_sdk: NetworkDefenderSDK
) -> None:
    old = datetime.now(UTC) - timedelta(days=3)
    readonly_sdk._alert_service.repository.save(
        Alert(
            timestamp=old,
            last_seen=old,
            severity=Severity.HIGH,
            rule_triggered="Ancient",
            description="old",
        )
    )
    _seed(readonly_sdk, 1)

    assert len(client.get(ALERTS, params={"hours": 1}).json()["items"]) == 1
    assert len(client.get(ALERTS, params={"hours": 168}).json()["items"]) == 2


def test_list_alerts_paginates(client: TestClient, readonly_sdk: NetworkDefenderSDK) -> None:
    _seed(readonly_sdk, 5)

    first = client.get(ALERTS, params={"limit": 2}).json()
    assert first["meta"]["count"] == 2
    assert first["meta"]["has_more"] is True

    second = client.get(ALERTS, params={"limit": 2, "offset": 2}).json()
    assert [item["rule_triggered"] for item in second["items"]] == ["Rule2", "Rule1"]


def test_page_size_is_capped(client: TestClient) -> None:
    response = client.get(ALERTS, params={"limit": 100_000})
    assert response.status_code == 422
    assert response.json()["error"]["code"] == "validation_error"


def test_negative_offset_is_rejected(client: TestClient) -> None:
    assert client.get(ALERTS, params={"offset": -1}).status_code == 422


def test_unknown_severity_is_rejected(client: TestClient) -> None:
    response = client.get(ALERTS, params={"severity": "catastrophic"})
    assert response.status_code == 422
    assert response.json()["error"]["detail"][0]["field"].startswith("query")
