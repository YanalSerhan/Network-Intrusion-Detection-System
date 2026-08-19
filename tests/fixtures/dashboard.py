"""
Fixture for tests that serve the built dashboard.

Shared rather than file-local because the serving tests and the path-traversal
tests both need a directory that looks like a real build, and two copies of
that setup would be two chances for them to drift.
"""

from pathlib import Path

import pytest

from network_defender.api.routers import dashboard


@pytest.fixture()
def built_dashboard(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Point the router at a throwaway directory holding a built dashboard."""
    static = tmp_path / "static"
    assets = static / "assets"
    assets.mkdir(parents=True)
    (static / "index.html").write_text("<!doctype html><title>Network Defender</title>")
    (assets / "app.abc123.js").write_text("console.log('hi')")
    # Copied verbatim from public/ by the bundler, so they sit beside
    # index.html rather than under assets/ and are not content-hashed.
    (static / "theme.js").write_text("document.documentElement.dataset.theme = 'dark';")
    (static / "favicon.svg").write_text("<svg xmlns='http://www.w3.org/2000/svg'/>")

    monkeypatch.setattr(dashboard, "STATIC_DIR", static)
    monkeypatch.setattr(dashboard, "INDEX_FILE", static / "index.html")
    monkeypatch.setattr(dashboard, "ASSETS_DIR", assets)
    return static
