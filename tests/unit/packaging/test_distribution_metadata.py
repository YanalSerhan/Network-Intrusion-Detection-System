"""
What the built distribution claims, and what it contains.

A wheel is the only artefact anyone but its author uses, and it had never been
built: `pip install network-defender` produced a package whose entry point
died on startup, because config/, rules/ and migrations/ live at the
repository root and the wheel shipped only the Python. Every test passed
throughout, because the suite runs from the checkout where the missing
directories happen to be present.

These read pyproject.toml as data rather than building — a build belongs in
CI, not in a unit suite — and pin the declarations that made the difference.
"""

import tomllib
from pathlib import Path

from network_defender.shared.paths import PROJECT_ROOT
from network_defender.shared.version import __version__

PYPROJECT = tomllib.loads((PROJECT_ROOT / "pyproject.toml").read_text(encoding="utf-8"))
PROJECT = PYPROJECT["project"]


def test_the_wheel_bundles_everything_the_package_reads_at_startup() -> None:
    included = PYPROJECT["tool"]["hatch"]["build"]["targets"]["wheel"]["force-include"]
    assert set(included) == {"config", "rules", "migrations", "alembic.ini"}
    for source, destination in included.items():
        assert (PROJECT_ROOT / source).exists(), f"{source} is declared but absent"
        assert destination.startswith("network_defender/_bundled/")


def test_the_sdist_ships_the_source_and_not_the_research_output() -> None:
    included = PYPROJECT["tool"]["hatch"]["build"]["targets"]["sdist"]["include"]
    assert "/src" in included
    assert "/tests" in included, "a packager who cannot run the suite cannot verify the build"
    for excluded in ("/research", "/reports", "/notebooks", "/frontend", "/docs"):
        assert excluded not in included


def test_the_package_declares_what_it_runs_on_and_who_it_is_for() -> None:
    classifiers = PROJECT["classifiers"]
    assert any(c.startswith("Topic :: Security") for c in classifiers)
    assert "Typing :: Typed" in classifiers
    assert "Programming Language :: Python :: 3.12" in classifiers
    # PEP 639: the licence is an SPDX expression, so the deprecated classifier
    # would be a second, unchecked statement of the same thing.
    assert not any(c.startswith("License ::") for c in classifiers)
    assert PROJECT["license"] == "MIT"


def test_every_declared_url_points_at_something_named() -> None:
    urls = PROJECT["urls"]
    assert set(urls) >= {"Homepage", "Repository", "Issues"}
    assert all(url.startswith("https://") for url in urls.values())


def test_the_entry_point_names_a_callable_that_exists() -> None:
    from network_defender.cli.main import main

    assert PROJECT["scripts"]["network-defender"] == "network_defender.cli.main:main"
    assert callable(main)


def test_the_version_is_declared_once() -> None:
    """A wheel labelled differently from the API it serves is a support call."""
    assert PROJECT["version"] == __version__


def test_the_declared_version_survives_pep_440_normalisation() -> None:
    """
    `1.00` is not canonical: installed metadata reports it as `1.0`.

    That is a fact about PEP 440 rather than a mistake, and it is pinned here
    so nobody chases the difference between `network-defender --version` and
    `pip show network-defender` as a bug. Compare parsed versions, never the
    strings, when the two have to agree.
    """
    from importlib.metadata import version as installed_version

    from packaging.version import Version

    assert Version(installed_version("network-defender")) == Version(__version__)


def test_the_readme_the_metadata_points_at_is_there() -> None:
    assert (PROJECT_ROOT / PROJECT["readme"]).is_file()
    assert (PROJECT_ROOT / Path(PROJECT["license-files"][0])).is_file()
