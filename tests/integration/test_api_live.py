"""API tests for the live WebSocket handshake, snapshot and authentication."""


import pytest
from fastapi.testclient import TestClient

from network_defender.api.live.payloads import (
    FRAME_ALERTS,
    FRAME_STATS,
)
from network_defender.constants import ENV_API_KEY
from network_defender.services.alerts.models import Alert

WS_URL = "/ws/live"


# --------------------------------------------------------------------------
# Handshake and snapshot
# --------------------------------------------------------------------------


def test_client_receives_a_snapshot_on_connect(client: TestClient, seeded_alert: Alert) -> None:
    """A new dashboard must be populated immediately, not on the next alert."""
    with client.websocket_connect(WS_URL) as ws:
        stats = ws.receive_json()
        alerts = ws.receive_json()

    assert stats["type"] == FRAME_STATS
    assert stats["total_alerts"] == 1

    assert alerts["type"] == FRAME_ALERTS
    assert alerts["initial"] is True
    assert alerts["alerts"][0]["rule_triggered"] == "TcpPortScanDetector"


def test_snapshot_on_an_empty_system(client: TestClient) -> None:
    with client.websocket_connect(WS_URL) as ws:
        assert ws.receive_json()["total_alerts"] == 0
        assert ws.receive_json()["alerts"] == []


def test_alert_frames_match_the_rest_summary_shape(
    client: TestClient, seeded_alert: Alert
) -> None:
    """One alert type on the client, not two that drift apart."""
    rest = client.get("/api/v1/alerts").json()["items"][0]

    with client.websocket_connect(WS_URL) as ws:
        ws.receive_json()
        streamed = ws.receive_json()["alerts"][0]

    assert streamed.keys() == rest.keys()
    assert streamed["alert_id"] == rest["alert_id"]

# --------------------------------------------------------------------------
# Authentication
# --------------------------------------------------------------------------


def test_connection_is_open_when_no_key_is_configured(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv(ENV_API_KEY, raising=False)
    with client.websocket_connect(WS_URL) as ws:
        assert ws.receive_json()["type"] == FRAME_STATS


def test_connection_is_refused_without_a_token(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Rejected before accept(), so an unauthorised client sees no data at all."""
    monkeypatch.setenv(ENV_API_KEY, "expected-key")

    # noqa: B017 - starlette raises a bare Exception on a refused handshake
    with pytest.raises(Exception), client.websocket_connect(WS_URL) as ws:  # noqa: B017
        ws.receive_json()


def test_connection_is_accepted_with_the_right_token(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv(ENV_API_KEY, "expected-key")
    with client.websocket_connect(f"{WS_URL}?token=expected-key") as ws:
        assert ws.receive_json()["type"] == FRAME_STATS
