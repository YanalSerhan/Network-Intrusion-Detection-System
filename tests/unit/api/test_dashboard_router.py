"""
Tests for serving the built dashboard.

What this route has to get right is invisible from a normal page load:
index.html must never be cached, an unbuilt dashboard must say so rather than
404 into a mystery, and a path naming a real file must serve that file rather
than the SPA shell. Path containment is next door in
``test_dashboard_traversal.py``.
"""

from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from network_defender.api.routers import dashboard

DASHBOARD = "/dashboard"


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


@pytest.mark.parametrize("name", ["theme.js", "favicon.svg"])
def test_public_files_are_served_as_themselves(
    client: TestClient, built_dashboard: Path, name: str
) -> None:
    """
    Everything the bundler copies from public/ must not hit the SPA fallback.

    This is the quiet half of the SPA deployment bug. A catch-all that returns
    index.html for *every* unmatched path answers /dashboard/theme.js with
    HTML at status 200, and the browser refuses to execute it — "MIME type
    ('text/html') is not executable". Nothing 404s and nothing logs an error;
    the page just silently loses whatever that file did. Here it was the
    pre-paint theme script, so the dashboard flashed the wrong colours on
    every load.
    """
    response = client.get(f"{DASHBOARD}/{name}")

    assert response.status_code == 200
    assert "<!doctype html>" not in response.text.lower()


def test_a_client_side_route_still_falls_back(
    client: TestClient, built_dashboard: Path
) -> None:
    """Serving real files must not break the fallback it sits in front of."""
    response = client.get(f"{DASHBOARD}/rules")

    assert response.status_code == 200
    assert "Network Defender" in response.text
