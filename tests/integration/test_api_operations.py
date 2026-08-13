"""Tests for /statistics, /rules, /health, /config, auth and the OpenAPI spec."""

import pytest
from fastapi.testclient import TestClient

from network_defender.api.dependencies import API_KEY_HEADER
from network_defender.constants import ENV_API_KEY
from network_defender.sdk.sdk import NetworkDefenderSDK
from network_defender.services.alerts.models import Alert
from tests.fixtures.constants import PUBLIC_IP

STATISTICS = "/api/v1/statistics"
RULES = "/api/v1/rules"
HEALTH = "/api/v1/health"
CONFIG = "/api/v1/config"

# --------------------------------------------------------------------------
# Statistics
# --------------------------------------------------------------------------


def test_statistics_summary_is_empty_initially(client: TestClient) -> None:
    body = client.get(STATISTICS).json()
    assert body["total_alerts"] == 0
    assert body["top_talkers"] == []
    assert body["alerts_by_severity"]["high"] == 0


def test_statistics_summary_counts_alerts(client: TestClient, seeded_alert: Alert) -> None:
    body = client.get(STATISTICS).json()

    assert body["total_alerts"] == 1
    assert body["alerts_by_severity"]["high"] == 1
    assert body["total_packets_retained"] == 1
    assert body["top_talkers"] == [{"ip": PUBLIC_IP, "alert_count": 1}]


def test_statistics_timeseries(client: TestClient, sdk: NetworkDefenderSDK) -> None:
    assert client.get(f"{STATISTICS}/timeseries").json() == []

    sdk._database_service.statistics.record_snapshot(total_alerts=3, packets_per_second=42.0)
    series = client.get(f"{STATISTICS}/timeseries", params={"hours": 24}).json()

    assert len(series) == 1
    assert series[0]["packets_per_second"] == 42.0


def test_timeseries_window_is_validated(client: TestClient) -> None:
    assert client.get(f"{STATISTICS}/timeseries", params={"hours": 0}).status_code == 422
    assert client.get(f"{STATISTICS}/timeseries", params={"hours": 99999}).status_code == 422


# --------------------------------------------------------------------------
# Rules
# --------------------------------------------------------------------------


def test_list_rules(client: TestClient, seeded_rules: int) -> None:
    body = client.get(RULES).json()

    assert body["meta"]["total"] == seeded_rules
    names = {rule["name"] for rule in body["items"]}
    assert "TCP Port Scan" in names


def test_get_rule(client: TestClient, seeded_rules: int) -> None:
    body = client.get(f"{RULES}/TCP Port Scan").json()

    assert body["name"] == "TCP Port Scan"
    assert body["threshold"] == 15
    assert body["enabled"] is True
    assert body["conditions"][0]["field"] == "protocol"


def test_get_unknown_rule_is_404(client: TestClient, seeded_rules: int) -> None:
    response = client.get(f"{RULES}/No Such Rule")
    assert response.status_code == 404
    assert response.json()["error"]["code"] == "not_found"


def test_toggle_rule_off_and_on(client: TestClient, seeded_rules: int) -> None:
    disabled = client.patch(f"{RULES}/TCP Port Scan", json={"enabled": False})
    assert disabled.status_code == 200
    assert disabled.json()["enabled"] is False

    # Persisted, not just echoed.
    assert client.get(f"{RULES}/TCP Port Scan").json()["enabled"] is False

    enabled = client.patch(f"{RULES}/TCP Port Scan", json={"enabled": True})
    assert enabled.json()["enabled"] is True


def test_toggling_does_not_rewrite_the_yaml_file(
    client: TestClient, sdk: NetworkDefenderSDK, seeded_rules: int
) -> None:
    """A runtime override must leave the operator's files untouched."""
    engine = sdk._detection_service.rule_engine
    assert engine is not None and engine.loader.rules_dir is not None
    path = engine.loader.rules_dir / "tcp_port_scan.yaml"
    before = path.read_text()

    client.patch(f"{RULES}/TCP Port Scan", json={"enabled": False})
    assert path.read_text() == before


def test_toggle_unknown_rule_is_404(client: TestClient, seeded_rules: int) -> None:
    assert client.patch(f"{RULES}/Nope", json={"enabled": False}).status_code == 404


def test_toggle_requires_a_boolean(client: TestClient, seeded_rules: int) -> None:
    response = client.patch(f"{RULES}/TCP Port Scan", json={"enabled": "maybe"})
    assert response.status_code == 422


def test_reload_restores_disabled_rules(client: TestClient, seeded_rules: int) -> None:
    """Files on disk are the source of truth, so a reload clears overrides."""
    client.patch(f"{RULES}/TCP Port Scan", json={"enabled": False})

    reload = client.post(f"{RULES}/reload")
    assert reload.status_code == 200
    assert reload.json() == {"status": "success", "loaded_rules_count": seeded_rules}
    assert client.get(f"{RULES}/TCP Port Scan").json()["enabled"] is True


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
    client: TestClient, sdk: NetworkDefenderSDK, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A broken instance must leave the load balancer rather than serve errors."""
    monkeypatch.setattr(
        sdk._database_service, "health_check", lambda: {"status": "error", "running": False}
    )
    response = client.get(HEALTH)

    assert response.status_code == 503
    assert response.json()["status"] == "degraded"


def test_liveness_still_passes_when_the_database_is_down(
    client: TestClient, sdk: NetworkDefenderSDK, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Otherwise an orchestrator would restart healthy pods during a DB blip."""
    monkeypatch.setattr(
        sdk._database_service, "health_check", lambda: {"status": "error", "running": False}
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


# --------------------------------------------------------------------------
# Contract
# --------------------------------------------------------------------------


def test_openapi_document_is_generated(client: TestClient) -> None:
    spec = client.get("/openapi.json").json()

    assert spec["info"]["title"] == "Network Defender API"
    assert {"alerts", "packets", "statistics", "rules", "health", "config"} <= {
        tag["name"] for tag in spec["tags"]
    }


def test_every_documented_endpoint_is_versioned(client: TestClient) -> None:
    spec = client.get("/openapi.json").json()
    assert all(path.startswith("/api/v1/") for path in spec["paths"])


def test_swagger_ui_is_served(client: TestClient) -> None:
    assert client.get("/docs").status_code == 200


def test_unknown_routes_use_the_standard_error_shape(client: TestClient) -> None:
    response = client.get("/api/v1/does-not-exist")
    assert response.status_code == 404
    assert response.json()["error"]["code"] == "not_found"


def test_wrong_method_uses_the_standard_error_shape(client: TestClient) -> None:
    response = client.delete("/api/v1/alerts")
    assert response.status_code == 405
    assert "error" in response.json()


def test_unhandled_errors_do_not_leak_internals(
    client: TestClient, sdk: NetworkDefenderSDK, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A stack trace belongs in the logs, not in the response body."""

    def explode(*args: object, **kwargs: object) -> None:
        raise RuntimeError("database password is hunter2")

    monkeypatch.setattr(sdk, "list_alerts", explode)
    raw_client = TestClient(client.app, raise_server_exceptions=False)

    response = raw_client.get("/api/v1/alerts")
    assert response.status_code == 500
    assert response.json()["error"] == {
        "code": "internal_error",
        "message": "An internal error occurred.",
        "detail": None,
    }
    assert "hunter2" not in response.text
