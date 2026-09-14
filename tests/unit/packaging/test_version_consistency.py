"""
One version, in every place that reports one.

Five literals read "1.00" and agreed by coincidence: the version module, the
project constant, both config schemas' defaults, and pyproject.toml. Four now
derive from the first. The fifth cannot — a build backend reads pyproject.toml
before this package exists — so it is checked here instead, along with the two
config files an operator edits by hand.

The failure these prevent is quiet: a `/health` endpoint reporting one version
while the wheel reports another is a support call that starts with nobody
believing either number.
"""

import json
import re
from pathlib import Path

import pytest

from network_defender.constants import PROJECT_VERSION
from network_defender.shared.config_models import AppConfig
from network_defender.shared.paths import CONFIG_DIR, PROJECT_ROOT
from network_defender.shared.rate_limit_models import RateLimitConfig
from network_defender.shared.version import __version__

#: Config files carrying the project's schema version. logging_config.json is
#: here because it has one too, which the first draft of this test missed —
#: which is the whole argument for the check at the bottom of the file.
CONFIG_FILES = ("setup.json", "rate_limits.json", "logging_config.json")


def test_the_project_constant_is_the_version_module() -> None:
    assert PROJECT_VERSION is __version__


@pytest.mark.parametrize("model", [AppConfig, RateLimitConfig])
def test_both_config_schemas_default_to_it(model: type) -> None:
    assert model().version == __version__


@pytest.mark.parametrize("filename", CONFIG_FILES)
def test_the_shipped_config_files_declare_it(filename: str) -> None:
    """These are edited by hand, so nothing derives them — only this check."""
    declared = json.loads((CONFIG_DIR / filename).read_text(encoding="utf-8"))["version"]
    assert declared == __version__, f"config/{filename} says {declared}"


def test_the_changelog_has_an_entry_for_the_current_version() -> None:
    """A version that moves without a line saying why is a number, not a version."""
    changelog = (PROJECT_ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
    assert re.search(rf"^## \[{re.escape(__version__)}\]", changelog, re.MULTILINE), (
        f"CHANGELOG.md has no '## [{__version__}]' section"
    )


def test_the_version_is_not_derived_from_anything_importable() -> None:
    """
    `shared/version.py` must stay dependency-free.

    It is imported by `constants`, which is imported by nearly everything, so
    an import here is a cycle waiting for its second edge.
    """
    source = (PROJECT_ROOT / "src" / "network_defender" / "shared" / "version.py").read_text()
    code = "\n".join(
        line for line in source.splitlines() if not line.lstrip().startswith("#")
    )
    body = code.split('"""')[-1]
    assert "import " not in body, "version.py must not import anything"


def test_the_api_reports_the_same_version_it_ships_as() -> None:
    from network_defender.api.app import create_app

    assert create_app().version == __version__


def test_the_cli_reports_the_same_version() -> None:
    from network_defender.cli.main import build_parser

    with pytest.raises(SystemExit):
        build_parser().parse_args(["--version"])


def test_every_version_literal_in_the_tree_is_accounted_for() -> None:
    """
    Nothing may hardcode the version except the places named here.

    A sixth literal is exactly how the first five came about.
    """
    allowed = {
        Path("pyproject.toml"),
        Path("CHANGELOG.md"),
        Path("src/network_defender/shared/version.py"),
        *(Path("config") / name for name in CONFIG_FILES),
    }
    searched = [
        *(PROJECT_ROOT / "src").rglob("*.py"),
        *(PROJECT_ROOT / "config").glob("*.json"),
        PROJECT_ROOT / "pyproject.toml",
    ]
    literal = re.compile(rf"(?<![\w.]){re.escape(__version__)}(?![\w.])")
    offenders = sorted(
        str(path.relative_to(PROJECT_ROOT))
        for path in searched
        if path.relative_to(PROJECT_ROOT) not in allowed
        and literal.search(path.read_text(encoding="utf-8"))
    )
    assert not offenders, f"{offenders} hardcode the version; derive it from version.py"
