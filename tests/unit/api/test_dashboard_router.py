"""
Tests for serving the built dashboard.

Three things here are security- or deployment-critical and none of them are
visible from a normal page load: the asset route must not serve files from
outside its directory, index.html must never be cached, and an unbuilt
dashboard must say so rather than 404 into a mystery.
"""

from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from network_defender.api.routers import dashboard

DASHBOARD = "/dashboard"


@pytest.fixture()
def built_dashboard(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Point the router at a throwaway directory holding a built dashboard."""
    static = tmp_path / "static"
    assets = static / "assets"
    assets.mkdir(parents=True)
    (static / "index.html").write_text("<!doctype html><title>Network Defender</title>")
    (assets / "app.abc123.js").write_text("console.log('hi')")

    monkeypatch.setattr(dashboard, "STATIC_DIR", static)
    monkeypatch.setattr(dashboard, "INDEX_FILE", static / "index.html")
    monkeypatch.setattr(dashboard, "ASSETS_DIR", assets)
    return static


def test_an_unbuilt_dashboard_explains_itself(
    client: TestClient, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """A 404 would send an operator hunting for a routing bug that isn't there."""
    monkeypatch.setattr(dashboard, "INDEX_FILE", tmp_path / "absent.html")

    response = client.get(DASHBOARD)
    assert response.status_code == 503
    assert response.json()["error"]["code"] == "dashboard_not_built"


def test_the_spa_shell_is_served_and_never_cached(
    client: TestClient, built_dashboard: Path
) -> None:
    """A cached index.html pins browsers to bundle hashes that no longer exist."""
    response = client.get(DASHBOARD)

    assert response.status_code == 200
    assert "no-store" in response.headers["cache-control"]


def test_deep_links_fall_back_to_the_shell(client: TestClient, built_dashboard: Path) -> None:
    """Reloading on a client-side route must not 404."""
    response = client.get(f"{DASHBOARD}/alerts/8a1f2c3d-0000-0000-0000-000000000000")

    assert response.status_code == 200
    assert "Network Defender" in response.text


def test_hashed_assets_are_cached_forever(client: TestClient, built_dashboard: Path) -> None:
    """Content-hashed filenames make an immutable cache header safe."""
    response = client.get(f"{DASHBOARD}/assets/app.abc123.js")

    assert response.status_code == 200
    assert "immutable" in response.headers["cache-control"]


def test_a_missing_asset_is_a_404_not_the_shell(
    client: TestClient, built_dashboard: Path
) -> None:
    """Returning HTML for a missing script would break the page silently."""
    response = client.get(f"{DASHBOARD}/assets/gone.js")

    assert response.status_code == 404
    assert response.json()["error"]["code"] == "not_found"


@pytest.mark.parametrize(
    "escape",
    ["../index.html", "../../etc/passwd", "sub/../../index.html"],
)
def test_asset_paths_cannot_escape_the_assets_directory(
    built_dashboard: Path, escape: str
) -> None:
    """
    Without the containment check this route serves arbitrary host files.

    Called directly rather than over HTTP: both httpx and Starlette normalise
    `..` out of a URL path before routing, so a request can never demonstrate
    that the guard inside the handler is what stops the traversal.
    """
    response = dashboard.get_asset(escape)

    assert response.status_code == 404
