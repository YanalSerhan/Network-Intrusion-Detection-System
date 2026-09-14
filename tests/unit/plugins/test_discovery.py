"""
The two routes a plugin gets in by, and what happens when one is broken.

Entry points are the primary route and the one a packaged extension uses:
install the distribution and it is found, uninstall it and it is gone. Testing
that properly would mean building and installing a distribution mid-suite, so
the entry point itself is substituted here and the rest — importing, isolating
failures, deduplicating against the configured route — is real.
"""

from collections.abc import Callable
from importlib.metadata import EntryPoint

import pytest

from network_defender.plugins import discovery

GROUP = "network_defender.detectors"
PLUGIN = "tests.fixtures.example_plugin.detectors"

#: Declares a set of entry points for the duration of one test.
Declare = Callable[..., None]


def _entry_points(*values: str) -> list[EntryPoint]:
    return [
        EntryPoint(name=f"plugin{index}", value=value, group=GROUP)
        for index, value in enumerate(values)
    ]


@pytest.fixture
def declared(monkeypatch: pytest.MonkeyPatch) -> Declare:
    """Substitute the installed entry points with a set named by the test."""

    def declare(*values: str) -> None:
        monkeypatch.setattr(
            discovery, "entry_points", lambda group: _entry_points(*values)  # noqa: ARG005
        )

    return declare


def test_an_entry_point_module_is_imported(declared: Declare) -> None:
    declared(PLUGIN)
    assert [m.__name__ for m in discovery.discover_modules(GROUP)] == [PLUGIN]


def test_an_entry_point_may_name_an_attribute(declared: Declare) -> None:
    """`pkg.mod:Class` is legal; the registry scans modules, so the class half is dropped."""
    declared(f"{PLUGIN}:JumboFrameDetector")
    assert [m.__name__ for m in discovery.discover_modules(GROUP)] == [PLUGIN]


def test_a_broken_entry_point_does_not_take_the_others_with_it(
    declared: Declare, caplog: pytest.LogCaptureFixture
) -> None:
    declared("tests.fixtures.nothing_here", PLUGIN)
    assert [m.__name__ for m in discovery.discover_modules(GROUP)] == [PLUGIN]
    assert "nothing_here" in caplog.text


def test_the_log_says_which_route_a_failure_came_from(
    declared: Declare, caplog: pytest.LogCaptureFixture
) -> None:
    """A person debugging needs to know whether to look at config or at an install."""
    declared("tests.fixtures.nothing_here")
    discovery.discover_modules(GROUP, ["tests.fixtures.also_nothing"])

    assert "entry point" in caplog.text
    assert "configuration" in caplog.text


def test_a_module_declared_by_both_routes_loads_once(declared: Declare) -> None:
    declared(PLUGIN)
    assert len(discovery.discover_modules(GROUP, [PLUGIN])) == 1


def test_no_plugins_is_not_an_error(declared: Declare) -> None:
    declared()
    assert discovery.discover_modules(GROUP) == []
    assert discovery.discover_modules(GROUP, []) == []
