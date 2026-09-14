"""
The dependency graph, checked against the one the architecture claims.

A layering diagram is a drawing until something fails when the code stops
matching it. This computes the real graph from the imports and compares it
with the table below, so a new edge is a decision someone makes in this file
rather than a thing that happens.

The table is deliberately tighter than "no cycles". Cycles are the obvious
failure; the interesting ones are the quiet edges — an HTTP router importing a
database column width, a detector package depending on the façade that
depends on it — that work fine and mean the pieces can no longer be lifted out
separately.
"""

import ast
from collections import defaultdict
from pathlib import Path

import pytest

from network_defender.shared.paths import PROJECT_ROOT

SRC = PROJECT_ROOT / "src" / "network_defender"

#: Layer -> the layers it may import. Anything else fails.
ALLOWED: dict[str, set[str]] = {
    # Ingest. Owns the socket and the byte-level helpers.
    "capture": {"constants", "shared"},
    # Normalisation. Reads capture's byte helpers; nothing reads it but the
    # layers that consume packets.
    "parser": {"capture", "constants", "shared"},
    # Detection. Sees packets and nothing else — no database, no API, no
    # services. This is the layer most worth keeping liftable, because it is
    # the one an evaluation harness or a research notebook wants alone.
    "detectors": {"constants", "parser", "shared"},
    "rules": {"constants", "parser", "shared"},
    # Persistence. Depends on the domain models and the repository interface,
    # both of which live under services: the adapter depends on the port, not
    # the other way round.
    "database": {"constants", "parser", "rules", "services", "shared"},
    # Orchestration.
    "services": {
        "capture", "constants", "database", "detectors",
        "observability", "parser", "rules", "shared",
    },
    # The façade. Everything a caller reaches for goes through here.
    "sdk": {
        "capture", "constants", "database", "detectors", "observability",
        "parser", "rules", "services", "shared",
    },
    # Transport. Talks to the SDK, and to models for its response schemas —
    # never to the database, and never to a service's behaviour.
    "api": {"constants", "observability", "parser", "sdk", "services", "shared"},
    "cli": {"constants", "sdk", "services", "shared"},
    # A façade for plugin authors. Nothing inside the package imports it, which
    # is what keeps it from being a cycle.
    "plugins": {"detectors", "services", "shared"},
    "observability": {"shared"},
    "constants": {"shared"},
    "shared": set(),
    "(root)": {"cli", "constants", "detectors", "parser", "sdk", "services", "shared"},
}

#: Layers no other layer may import, and why. `plugins` is a façade for people
#: outside this repository; an internal importer would make it a cycle.
FACADES_NOTHING_INTERNAL_IMPORTS = {"plugins"}


def _layer(path: Path) -> str:
    relative = path.relative_to(SRC)
    return relative.parts[0] if len(relative.parts) > 1 else "(root)"


def _graph() -> dict[str, dict[str, list[str]]]:
    edges: dict[str, dict[str, list[str]]] = defaultdict(lambda: defaultdict(list))
    for path in sorted(SRC.rglob("*.py")):
        layer = _layer(path)
        for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
            for module in _imported_modules(node):
                parts = module.split(".")
                target = parts[1] if len(parts) > 1 else "(root)"
                if target != layer:
                    edges[layer][target].append(str(path.relative_to(SRC)))
    return edges


def _imported_modules(node: ast.AST) -> list[str]:
    if isinstance(node, ast.ImportFrom) and node.module:
        return [node.module] if node.module.startswith("network_defender") else []
    if isinstance(node, ast.Import):
        return [a.name for a in node.names if a.name.startswith("network_defender")]
    return []


GRAPH = _graph()


def test_every_layer_is_accounted_for() -> None:
    """A new top-level package must be placed in the table, not just added."""
    found = {_layer(path) for path in SRC.rglob("*.py")}
    assert found <= set(ALLOWED), f"unplaced layer(s): {sorted(found - set(ALLOWED))}"


@pytest.mark.parametrize("layer", sorted(ALLOWED))
def test_a_layer_imports_only_what_it_is_allowed_to(layer: str) -> None:
    actual = set(GRAPH.get(layer, {}))
    forbidden = actual - ALLOWED[layer]
    detail = {target: sorted(set(GRAPH[layer][target])) for target in forbidden}
    assert not forbidden, f"{layer} imports {sorted(forbidden)}: {detail}"


@pytest.mark.parametrize("facade", sorted(FACADES_NOTHING_INTERNAL_IMPORTS))
def test_nothing_inside_the_package_imports_a_facade(facade: str) -> None:
    importers = sorted(layer for layer, targets in GRAPH.items() if facade in targets)
    assert not importers, f"{importers} import {facade}, which makes it a cycle"


def test_the_detectors_can_be_lifted_out_on_their_own() -> None:
    """
    The property that makes the sensitivity analysis possible.

    `scripts/sensitivity/` replays a corpus through detectors with no database,
    no services and no SDK. That works because the detector layer depends on
    packets and configuration and nothing else, and it stops working silently
    the first time a detector reaches for an alert repository.
    """
    assert set(GRAPH["detectors"]) <= {"constants", "parser", "shared"}
