"""Tests for /alerts and /packets, happy and error paths."""

from datetime import UTC, datetime, timedelta
from uuid import uuid4

from fastapi.testclient import TestClient

from network_defender.constants import AlertStatus, Severity
from network_defender.sdk.sdk import NetworkDefenderSDK
from network_defender.services.alerts.models import Alert
from tests.fixtures.constants import PUBLIC_IP

ALERTS = "/api/v1/alerts"
PACKETS = "/api/v1/packets"


def _seed(sdk: NetworkDefenderSDK, count: int, severity: Severity = Severity.HIGH) -> None:
    now = datetime.now(UTC)
    for index in range(count):
        stamp = now + timedelta(seconds=index)
        sdk._alert_service.repository.save(
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


def test_list_alerts_returns_newest_first(client: TestClient, sdk: NetworkDefenderSDK) -> None:
    _seed(sdk, 3)
    names = [item["rule_triggered"] for item in client.get(ALERTS).json()["items"]]
    assert names == ["Rule2", "Rule1", "Rule0"]


def test_list_alerts_filters_by_severity(client: TestClient, sdk: NetworkDefenderSDK) -> None:
    _seed(sdk, 2, severity=Severity.HIGH)
    _seed(sdk, 1, severity=Severity.LOW)

    assert len(client.get(ALERTS, params={"severity": "low"}).json()["items"]) == 1
    assert len(client.get(ALERTS, params={"severity": "critical"}).json()["items"]) == 0


def test_list_alerts_filters_by_status(client: TestClient, seeded_alert: Alert) -> None:
    assert len(client.get(ALERTS, params={"status": "new"}).json()["items"]) == 1
    assert len(client.get(ALERTS, params={"status": "resolved"}).json()["items"]) == 0


def test_list_alerts_filters_by_time_window(
    client: TestClient, sdk: NetworkDefenderSDK
) -> None:
    old = datetime.now(UTC) - timedelta(days=3)
    sdk._alert_service.repository.save(
        Alert(
            timestamp=old,
            last_seen=old,
            severity=Severity.HIGH,
            rule_triggered="Ancient",
            description="old",
        )
    )
    _seed(sdk, 1)

    assert len(client.get(ALERTS, params={"hours": 1}).json()["items"]) == 1
    assert len(client.get(ALERTS, params={"hours": 168}).json()["items"]) == 2


def test_list_alerts_paginates(client: TestClient, sdk: NetworkDefenderSDK) -> None:
    _seed(sdk, 5)

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


# --------------------------------------------------------------------------
# Detail
# --------------------------------------------------------------------------


def test_get_alert_returns_full_detail(client: TestClient, seeded_alert: Alert) -> None:
    body = client.get(f"{ALERTS}/{seeded_alert.alert_id}").json()

    assert body["alert_id"] == str(seeded_alert.alert_id)
    assert body["evidence"] == {"unique_ports": 60}
    assert body["technique"] == "T1046"
    assert body["description"].startswith("TCP Port Scan")


def test_get_unknown_alert_is_404(client: TestClient) -> None:
    response = client.get(f"{ALERTS}/{uuid4()}")
    assert response.status_code == 404
    assert response.json()["error"]["code"] == "not_found"


def test_malformed_alert_id_is_422(client: TestClient) -> None:
    assert client.get(f"{ALERTS}/not-a-uuid").status_code == 422


# --------------------------------------------------------------------------
# Evidence
# --------------------------------------------------------------------------


def test_alert_packets_are_returned(client: TestClient, seeded_alert: Alert) -> None:
    body = client.get(f"{ALERTS}/{seeded_alert.alert_id}/packets").json()

    assert len(body) == 1
    assert body[0]["src_ip"] == PUBLIC_IP
    assert body[0]["fields"]["tcp_flags"]["syn"] is True


def test_packets_for_unknown_alert_is_404(client: TestClient) -> None:
    assert client.get(f"{ALERTS}/{uuid4()}/packets").status_code == 404


# --------------------------------------------------------------------------
# Triage
# --------------------------------------------------------------------------


def test_status_can_be_updated(client: TestClient, seeded_alert: Alert) -> None:
    response = client.patch(
        f"{ALERTS}/{seeded_alert.alert_id}", json={"status": "acknowledged"}
    )
    assert response.status_code == 200
    assert response.json()["status"] == "acknowledged"

    # Persisted, not just echoed back.
    assert client.get(f"{ALERTS}/{seeded_alert.alert_id}").json()["status"] == "acknowledged"


def test_status_update_on_unknown_alert_is_404(client: TestClient) -> None:
    response = client.patch(f"{ALERTS}/{uuid4()}", json={"status": "resolved"})
    assert response.status_code == 404


def test_invalid_status_is_rejected(client: TestClient, seeded_alert: Alert) -> None:
    response = client.patch(f"{ALERTS}/{seeded_alert.alert_id}", json={"status": "banana"})
    assert response.status_code == 422


def test_missing_body_is_rejected(client: TestClient, seeded_alert: Alert) -> None:
    assert client.patch(f"{ALERTS}/{seeded_alert.alert_id}", json={}).status_code == 422


def test_every_triage_status_is_accepted(client: TestClient, seeded_alert: Alert) -> None:
    for status in AlertStatus:
        response = client.patch(
            f"{ALERTS}/{seeded_alert.alert_id}", json={"status": status.value}
        )
        assert response.status_code == 200


# --------------------------------------------------------------------------
# Enrichment
# --------------------------------------------------------------------------


def test_enrich_on_demand(client: TestClient, seeded_alert: Alert) -> None:
    """No providers are configured here, so this exercises the fail-open path."""
    response = client.post(f"{ALERTS}/{seeded_alert.alert_id}/enrich")
    assert response.status_code == 200
    assert response.json()["alert_id"] == str(seeded_alert.alert_id)


def test_enrich_unknown_alert_is_404(client: TestClient) -> None:
    assert client.post(f"{ALERTS}/{uuid4()}/enrich").status_code == 404


# --------------------------------------------------------------------------
# Packets resource
# --------------------------------------------------------------------------


def test_list_packets(client: TestClient, seeded_alert: Alert) -> None:
    body = client.get(PACKETS).json()
    assert body["meta"]["count"] == 1
    assert body["items"][0]["protocol"] == "tcp"


def test_list_packets_filters(client: TestClient, seeded_alert: Alert) -> None:
    assert len(client.get(PACKETS, params={"protocol": "tcp"}).json()["items"]) == 1
    assert len(client.get(PACKETS, params={"protocol": "udp"}).json()["items"]) == 0
    assert len(client.get(PACKETS, params={"src_ip": PUBLIC_IP}).json()["items"]) == 1
    assert (
        len(client.get(PACKETS, params={"alert_id": str(seeded_alert.alert_id)}).json()["items"])
        == 1
    )


def test_get_unknown_packet_is_404(client: TestClient) -> None:
    response = client.get(f"{PACKETS}/999999")
    assert response.status_code == 404
    assert response.json()["error"]["code"] == "not_found"


def test_packet_id_must_be_positive(client: TestClient) -> None:
    assert client.get(f"{PACKETS}/0").status_code == 422
