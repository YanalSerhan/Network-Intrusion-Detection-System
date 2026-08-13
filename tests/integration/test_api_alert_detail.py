"""API tests for a single alert: detail, evidence, triage and enrichment."""

from uuid import uuid4

from fastapi.testclient import TestClient

from network_defender.constants import AlertStatus
from network_defender.services.alerts.models import Alert
from tests.fixtures.constants import PUBLIC_IP

ALERTS = "/api/v1/alerts"
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
