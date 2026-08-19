"""
Dashboard static file serving.

Data Setup:  Serves the Vite build output from `api/static/`.
Data Input:  Browser requests for the SPA and its assets.
Data Output: index.html, hashed asset bundles.

Two things this has to get right:

  * **History fallback.** The dashboard is a single-page app using client-side
    routing, so a browser reload on `/dashboard/alerts/<uuid>` asks the server
    for a path that has no file. Without a catch-all returning index.html,
    every deep link and refresh 404s — the classic SPA deployment bug.

    The catch-all has to check for a real file first, though. Without that,
    everything the bundler copies from `public/` — the favicon, the icon
    sprite, the pre-paint theme script — is answered with index.html at status
    200, and the browser refuses to execute or render HTML it asked for as
    JavaScript or SVG. That is the second half of the same deployment bug and
    it fails more quietly than a 404.

  * **Cache headers.** Vite fingerprints asset filenames, so bundles are safe
    to cache forever, but `index.html` must never be cached: it is the file
    that points at the current bundle hashes, and a stale copy pins browsers
    to a deleted build.

The dashboard is unauthenticated because it ships no data — every byte it
displays comes from `/api/v1`, which enforces the API key itself.
"""

from pathlib import Path

from fastapi import APIRouter
from fastapi.responses import FileResponse, JSONResponse
from starlette.responses import Response

STATIC_DIR = Path(__file__).resolve().parent.parent / "static"
INDEX_FILE = STATIC_DIR / "index.html"
ASSETS_DIR = STATIC_DIR / "assets"

#: One year, the maximum meaningful value; safe only because filenames are
#: content-hashed by the bundler.
ASSET_CACHE_CONTROL = "public, max-age=31536000, immutable"
INDEX_CACHE_CONTROL = "no-cache, no-store, must-revalidate"

router = APIRouter(prefix="/dashboard", tags=["dashboard"])


def dashboard_is_built() -> bool:
    """Return True if a built dashboard is present on disk."""
    return INDEX_FILE.is_file()


def _not_built() -> JSONResponse:
    """Explain how to build the dashboard instead of returning a bare 404."""
    return JSONResponse(
        status_code=503,
        content={
            "error": {
                "code": "dashboard_not_built",
                "message": "The dashboard has not been built.",
                "detail": "Run `npm install && npm run build` in frontend/.",
            }
        },
    )


@router.get("/assets/{asset_path:path}", include_in_schema=False)
def get_asset(asset_path: str) -> Response:
    """
    Serve a hashed asset bundle.

    Args:
        asset_path: Path of the asset relative to the assets directory.

    Returns:
        The asset with a long-lived cache header, or a 404 body.
    """
    candidate = (ASSETS_DIR / asset_path).resolve()

    # Containment check: without it, `..%2f..%2fetc/passwd` would escape the
    # assets directory and serve arbitrary files off the host.
    if not candidate.is_file() or ASSETS_DIR.resolve() not in candidate.parents:
        return JSONResponse(
            status_code=404,
            content={"error": {"code": "not_found", "message": "Asset not found."}},
        )

    return FileResponse(candidate, headers={"Cache-Control": ASSET_CACHE_CONTROL})


def _static_file(spa_path: str) -> Path | None:
    """
    Return the real file a dashboard path names, if there is one.

    Args:
        spa_path: The requested path, relative to /dashboard.

    Returns:
        The file, or None when the path is a client-side route.
    """
    if not spa_path:
        return None
    candidate = (STATIC_DIR / spa_path).resolve()
    root = STATIC_DIR.resolve()
    # Same containment check as the asset route: without it, `../../etc/passwd`
    # escapes the static directory.
    if candidate.is_file() and root in candidate.parents:
        return candidate
    return None


@router.get("", include_in_schema=False)
@router.get("/{spa_path:path}", include_in_schema=False)
def serve_dashboard(spa_path: str = "") -> Response:
    """
    Serve a real static file if the path names one, else the SPA shell.

    Client-side routes have no corresponding file, so every unmatched path
    returns index.html and lets the router resolve it in the browser. Paths
    that *do* name a file — the favicon, the icon sprite, the theme script —
    must not, because a browser will not execute a script served as HTML.

    Args:
        spa_path: The requested path, relative to /dashboard.

    Returns:
        The named file, index.html, or a 503 explaining that the dashboard is
        not built.
    """
    if not dashboard_is_built():
        return _not_built()

    static_file = _static_file(spa_path)
    if static_file is not None:
        return FileResponse(static_file, headers={"Cache-Control": INDEX_CACHE_CONTROL})
    return FileResponse(INDEX_FILE, headers={"Cache-Control": INDEX_CACHE_CONTROL})
