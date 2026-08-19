"""
Tests that dashboard paths cannot escape the directories they are served from.

Both routes resolve a user-supplied path against a directory, which is the
shape that serves /etc/passwd when the containment check is missing or wrong.
Split from the serving tests so the file name says which kind of failure a red
build means.

Every test here calls the handler directly rather than going over HTTP. Both
httpx and Starlette normalise `..` out of a URL path before routing, so a
request can never demonstrate that the guard inside the handler is what stops
the traversal — it would pass with the guard deleted.
"""

from pathlib import Path

import pytest
from fastapi.responses import FileResponse

from network_defender.api.routers import dashboard

ESCAPES = ["../index.html", "../../etc/passwd", "sub/../../index.html"]


@pytest.mark.parametrize("escape", ESCAPES)
def test_spa_paths_cannot_escape_the_static_directory(
    built_dashboard: Path, escape: str
) -> None:
    response = dashboard.serve_dashboard(escape)

    assert isinstance(response, FileResponse)
    assert Path(response.path) == built_dashboard / "index.html"


@pytest.mark.parametrize("escape", ESCAPES)
def test_asset_paths_cannot_escape_the_assets_directory(
    built_dashboard: Path, escape: str
) -> None:
    response = dashboard.get_asset(escape)

    assert response.status_code == 404
