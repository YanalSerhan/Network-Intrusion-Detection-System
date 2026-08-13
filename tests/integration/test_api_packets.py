"""API tests for the packets resource."""


from fastapi.testclient import TestClient

from network_defender.services.alerts.models import Alert
from tests.fixtures.constants import PUBLIC_IP

PACKETS = "/api/v1/packets"


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
