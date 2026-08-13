"""API tests for the health probes and the config endpoint."""

import pytest
from fastapi.testclient import TestClient

from network_defender.api.dependencies import API_KEY_HEADER
from network_defender.constants import ENV_API_KEY
from network_defender.sdk.sdk import NetworkDefenderSDK

HEALTH = "/api/v1/health"
CONFIG = "/api/v1/config"


# --------------------------------------------------------------------------
# Health
# --------------------------------------------------------------------------


def test_liveness_needs_nothing(client: TestClient) -> None:
    response = client.get(f"{HEALTH}/live")
    assert response.status_code == 200
    assert response.json() == {"status": "alive"}


def test_readiness_reports_components(client: TestClient) -> None:
    response = client.get(HEALTH)
    assert response.status_code == 200

    body = response.json()
    assert body["status"] == "ok"
    assert body["components"]["database"]["status"] == "ok"
    assert body["components"]["alerting"]["status"] == "ok"


def test_readiness_returns_503_when_a_component_fails(
    client: TestClient, readonly_sdk: NetworkDefenderSDK, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A broken instance must leave the load balancer rather than serve errors."""
    monkeypatch.setattr(
        readonly_sdk._database_service,
        "health_check",
        lambda: {"status": "error", "running": False},
    )
    response = client.get(HEALTH)

    assert response.status_code == 503
    assert response.json()["status"] == "degraded"


def test_liveness_still_passes_when_the_database_is_down(
    client: TestClient, readonly_sdk: NetworkDefenderSDK, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Otherwise an orchestrator would restart healthy pods during a DB blip."""
    monkeypatch.setattr(
        readonly_sdk._database_service,
        "health_check",
        lambda: {"status": "error", "running": False},
    )
    assert client.get(f"{HEALTH}/live").status_code == 200

# --------------------------------------------------------------------------
# Config
# --------------------------------------------------------------------------


def test_config_returns_non_secret_settings(client: TestClient) -> None:
    body = client.get(CONFIG).json()

    assert body["api"]["port"] == 8000
    assert body["retention_days"] == 30
    assert "evaluation_interval_seconds" in body["detection"]


def test_config_never_leaks_credentials(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("DATABASE_URL", "postgresql://user:hunter2@db/nd")
    monkeypatch.setenv(ENV_API_KEY, "super-secret")

    raw = client.get(CONFIG, headers={API_KEY_HEADER: "super-secret"}).text

    assert "hunter2" not in raw
    assert "super-secret" not in raw
    assert '"API_KEY":true' in raw.replace(" ", "")
