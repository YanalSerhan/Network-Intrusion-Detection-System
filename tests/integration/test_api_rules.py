"""API tests for listing, toggling and reloading rules."""

from fastapi.testclient import TestClient

from network_defender.sdk.sdk import NetworkDefenderSDK

RULES = "/api/v1/rules"
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
    client: TestClient, readonly_sdk: NetworkDefenderSDK, seeded_rules: int
) -> None:
    """A runtime override must leave the operator's files untouched."""
    engine = readonly_sdk._detection_service.rule_engine
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
