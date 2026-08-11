"""
Export the OpenAPI schema to docs/openapi.json.

Run from the repository root:

    uv run python scripts/export_openapi.py

Committing the generated spec means API changes show up as a reviewable diff:
a removed field or a changed status code is visible in the pull request rather
than discovered by a client at runtime. Wire it into CI to fail on drift.
"""

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from network_defender.api.app import create_app  # noqa: E402
from network_defender.shared.paths import PROJECT_ROOT  # noqa: E402

OUTPUT_PATH = PROJECT_ROOT / "docs" / "openapi.json"


def export() -> Path:
    """
    Write the OpenAPI document to docs/openapi.json.

    Returns:
        The path written.
    """
    # A dummy SDK is not needed: schema generation only inspects routes and
    # models, so the app is built without a lifespan and never serves traffic.
    app = create_app(sdk=None)
    app.router.lifespan_context = None  # type: ignore[assignment]

    spec = app.openapi()
    OUTPUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT_PATH.write_text(json.dumps(spec, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return OUTPUT_PATH


if __name__ == "__main__":
    path = export()
    print(f"OpenAPI schema written to {path}")
