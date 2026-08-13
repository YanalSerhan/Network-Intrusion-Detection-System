"""API tests for the OpenAPI document and the shared error shape."""

import pytest
from fastapi.testclient import TestClient

from network_defender.sdk.sdk import NetworkDefenderSDK

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
    client: TestClient, readonly_sdk: NetworkDefenderSDK, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A stack trace belongs in the logs, not in the response body."""

    def explode(*args: object, **kwargs: object) -> None:
        raise RuntimeError("database password is hunter2")

    monkeypatch.setattr(readonly_sdk, "list_alerts", explode)
    raw_client = TestClient(client.app, raise_server_exceptions=False)

    response = raw_client.get("/api/v1/alerts")
    assert response.status_code == 500
    assert response.json()["error"] == {
        "code": "internal_error",
        "message": "An internal error occurred.",
        "detail": None,
    }
    assert "hunter2" not in response.text
