"""
Tests that no source file exceeds the 150-line limit in ADR 4.

The limit is a proxy, and worth stating why it is the one the project chose:
a file that outgrows a screen and a half is usually holding two concerns, and
splitting it is easier while it is 160 lines than once it is 600. Nothing here
claims 150 is special — only that a number a build enforces is worth more than
a number a review is supposed to remember.

It had already slipped twice during Milestone 15: adding required docstrings
pushed two files over, and both were only noticed because someone happened to
run `wc -l`. This is that check, run every time.
"""

from pathlib import Path

import pytest

from network_defender.shared.paths import PROJECT_ROOT

#: ADR 4.
MAX_LINES = 150

#: Directories whose Python files are subject to the limit.
CHECKED_DIRECTORIES = ("src", "tests", "scripts")

#: Alembic writes these, and a migration is a historical record: it must not
#: be reformatted to satisfy a rule adopted after it was generated. The
#: post-write hook keeps new ones lint-clean; length is not its business.
EXEMPT_DIRECTORIES = ("migrations",)


def _python_files() -> list[Path]:
    """Return every Python file the limit applies to."""
    files: list[Path] = []
    for directory in CHECKED_DIRECTORIES:
        root = PROJECT_ROOT / directory
        files.extend(
            path
            for path in root.rglob("*.py")
            if not any(part in EXEMPT_DIRECTORIES or part.startswith(".") for part in path.parts)
        )
    return sorted(files)


def _relative(path: Path) -> str:
    """Return the path as written in a commit message."""
    return str(path.relative_to(PROJECT_ROOT))


@pytest.mark.parametrize("path", _python_files(), ids=_relative)
def test_file_is_within_the_line_limit(path: Path) -> None:
    """Every checked file must fit inside ADR 4's limit."""
    lines = len(path.read_text(encoding="utf-8").splitlines())

    assert lines <= MAX_LINES, (
        f"{_relative(path)} is {lines} lines, over the {MAX_LINES}-line limit "
        f"in ADR 4. Split it by concern rather than raising the limit."
    )


def test_the_check_actually_found_files() -> None:
    """A glob that silently matches nothing would pass forever."""
    files = _python_files()

    assert len(files) > 100, f"Only found {len(files)} files to check — is the glob right?"
