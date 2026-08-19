"""
Tests that nothing credential-shaped is committed to source.

Narrow on purpose. gitleaks covers the general case in CI with a much larger
rule set; this runs in milliseconds on every test run and catches the shapes
most likely to be pasted in during development, while the mistake is still one
`git reset` away.

Every pattern here was checked by planting a matching literal and confirming
the test objected — which is how three of them got fixed. A scanner nobody has
watched fail is a scanner nobody knows the state of.
"""

import re
from pathlib import Path

from network_defender.shared.paths import PROJECT_ROOT

SRC = PROJECT_ROOT / "src"

#: Shapes that are a credential wherever they appear. Deliberately narrow —
#: a scanner that cries wolf gets disabled, and gitleaks covers the general
#: case in CI.
CREDENTIAL_PATTERNS = (
    # Segmented on purpose: `sk-live-...` and `sk-test-...` are as common as
    # the unsegmented form, and a pattern that stops at the first hyphen
    # misses them — which this one did until a mutation check caught it.
    re.compile(r"sk-[A-Za-z0-9_-]{16,}"),
    re.compile(r"AKIA[0-9A-Z]{16}"),
    re.compile(r"gh[pousr]_[A-Za-z0-9]{20,}"),
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
    re.compile(r"xox[baprs]-[A-Za-z0-9-]{10,}"),
    # A long literal assigned to something named like a credential. Two
    # guards keep it off ordinary code: the value must contain a digit and run
    # to 20 characters, which `evidence_key = "connection_count"` does not;
    # and a case-sensitive lookahead skips values that are themselves
    # SCREAMING_SNAKE_CASE, since those name an environment variable rather
    # than hold one's value — `ENV_ABUSEIPDB_API_KEY = "ABUSEIPDB_API_KEY"` is
    # the constant that keeps the real key out of source, not a leak of it.
    re.compile(
        r"(?i)([a-z0-9_]*key|password|passwd|secret|token|credential)\s*[:=]\s*"
        r"[\"'](?!(?-i:[A-Z0-9_]+)[\"'])(?=[^\"']*[0-9])[^\"'\s]{20,}[\"']"
    ),
)


def _python_sources() -> list[Path]:
    """Every shipped Python file."""
    return sorted(SRC.rglob("*.py"))



def test_no_credential_shaped_literal_is_committed() -> None:
    """A key pasted into source is a key that is now in history forever."""
    for path in _python_sources():
        text = path.read_text()
        for pattern in CREDENTIAL_PATTERNS:
            assert not pattern.search(text), (
                f"{path.relative_to(PROJECT_ROOT)} contains something shaped like a "
                f"credential ({pattern.pattern})."
            )
