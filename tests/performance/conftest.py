"""
Marks every test in this directory as a performance test.

`pyproject.toml` declares a `performance` marker and documents it as the way
to select or skip the throughput and latency floors, but nothing carried it,
so `pytest -m performance` collected zero tests and `-m "not performance"` ran
all of them. Applying it here rather than decorating each module keeps the
marker true for anything added to this directory later, which is the failure
mode a per-file `pytestmark` has.

The path filter is load-bearing: `pytest_collection_modifyitems` is a
session-scoped hook and receives every collected item, not only the ones under
the conftest that defines it. Without the filter this marks the whole suite,
and `-m "not performance"` then deselects all 1185 tests — which looks like a
green run.
"""

from pathlib import Path

import pytest

PERFORMANCE_DIR = Path(__file__).resolve().parent


def pytest_collection_modifyitems(items: list[pytest.Item]) -> None:
    """Add the `performance` marker to every test collected from this package."""
    for item in items:
        if PERFORMANCE_DIR in Path(str(item.path)).parents:
            item.add_marker(pytest.mark.performance)
