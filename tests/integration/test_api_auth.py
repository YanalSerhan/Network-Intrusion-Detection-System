"""API tests for API-key authentication and the endpoints exempt from it."""

import pytest
from fastapi.testclient import TestClient

from network_defender.api.dependencies import API_KEY_HEADER
from network_defender.constants import ENV_API_KEY

HEALTH = "/api/v1/health"
# --------------------------------------------------------------------------
# Authentication
# --------------------------------------------------------------------------


def test_auth_is_disabled_when_no_key_is_configured(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv(ENV_API_KEY, raising=False)
    assert client.get("/api/v1/alerts").status_code == 200


def test_missing_key_is_rejected_when_configured(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv(ENV_API_KEY, "expected-key")

    response = client.get("/api/v1/alerts")
    assert response.status_code == 401
    assert response.json()["error"]["code"] == "unauthorised"


def test_wrong_key_is_rejected(client: TestClient, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(ENV_API_KEY, "expected-key")
    response = client.get("/api/v1/alerts", headers={API_KEY_HEADER: "wrong"})
    assert response.status_code == 401


def test_correct_key_is_accepted(client: TestClient, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(ENV_API_KEY, "expected-key")
    response = client.get("/api/v1/alerts", headers={API_KEY_HEADER: "expected-key"})
    assert response.status_code == 200


def test_health_probes_stay_open_when_auth_is_on(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    """An orchestrator probing health has no credentials."""
    monkeypatch.setenv(ENV_API_KEY, "expected-key")

    assert client.get(f"{HEALTH}/live").status_code == 200
    assert client.get(HEALTH).status_code == 200
