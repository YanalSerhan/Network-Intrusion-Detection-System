"""
Tests that credentials only ever come from the environment.

Milestone 16 asks these to be *confirmed*. A confirmation someone performed
once is worth less than one the suite performs on every run: the working tree
changes, and the audit that found `.env-example` documenting two variables
nothing read was the audit nobody had run in months.

These are cheap, and each one fails loudly at the moment the invariant breaks
rather than at the review that happens quarters later.
"""

import re
import subprocess
from pathlib import Path

import pytest

from network_defender.constants import ENV_ABUSEIPDB_API_KEY, ENV_API_KEY
from network_defender.shared.paths import PROJECT_ROOT

SRC = PROJECT_ROOT / "src"
ENV_EXAMPLE = PROJECT_ROOT / ".env-example"

#: The one module allowed to read credentials out of the environment. Anywhere
#: else and the "secrets come from the environment, via one door" rule is a
#: convention rather than a fact.
SECRET_GATEWAY = SRC / "network_defender" / "shared" / "secrets.py"

#: Reads the environment for configuration, not credentials: it turns
#: ND__SECTION__KEY variables into config overrides and never touches a
#: secret's name.
CONFIG_OVERRIDE_READER = SRC / "network_defender" / "shared" / "config_env.py"

def _python_sources() -> list[Path]:
    """Every shipped Python file."""
    return sorted(SRC.rglob("*.py"))


def _env_example_names() -> set[str]:
    """Variable names the template documents, ignoring comments."""
    return {
        line.split("=", 1)[0].strip()
        for line in ENV_EXAMPLE.read_text().splitlines()
        if "=" in line and not line.lstrip().startswith("#")
    }


def test_only_the_secrets_module_reads_the_environment_for_credentials() -> None:
    """One door in. A second one is how a secret ends up somewhere it is not redacted."""
    offenders = [
        path.relative_to(PROJECT_ROOT)
        for path in _python_sources()
        if path not in (SECRET_GATEWAY, CONFIG_OVERRIDE_READER)
        and re.search(r"os\.(getenv|environ)", path.read_text())
    ]

    assert not offenders, (
        f"{offenders} read the environment directly. Credentials must go through "
        f"shared/secrets.py, which is where redaction and the .env fallback live."
    )


def test_every_documented_variable_is_one_the_code_reads() -> None:
    """
    A template entry nothing reads teaches a setting that does not exist.

    `.env-example` documented API_HOST and API_PORT for months. Setting either
    did nothing, and the real override was named differently — the most likely
    way an operator ends up bound to the wrong port with no error to explain it.
    """
    documented = _env_example_names()
    source = "\n".join(path.read_text() for path in _python_sources())

    unread = {
        name
        for name in documented
        if name not in source and f'"{name}"' not in source
    }

    assert not unread, (
        f"{sorted(unread)} are documented in .env-example but never read. Either wire "
        f"them up or remove them; a variable that silently does nothing is worse than "
        f"an undocumented one."
    )


@pytest.mark.parametrize("name", [ENV_API_KEY, ENV_ABUSEIPDB_API_KEY, "DATABASE_URL"])
def test_every_secret_the_code_reads_is_documented(name: str) -> None:
    """An operator should not have to read the source to find what to set."""
    assert name in ENV_EXAMPLE.read_text(), f"{name} is read by the code but undocumented."


def test_the_env_file_is_ignored_and_the_template_is_not() -> None:
    """The pair only works if exactly one of them is committable."""
    ignored = subprocess.run(
        ["git", "check-ignore", ".env"], cwd=PROJECT_ROOT, capture_output=True, text=True
    )
    assert ignored.returncode == 0, ".env is not git-ignored"

    tracked = subprocess.run(
        ["git", "ls-files", "--error-unmatch", ".env-example"],
        cwd=PROJECT_ROOT,
        capture_output=True,
        text=True,
    )
    assert tracked.returncode == 0, ".env-example is not committed"


def test_no_secret_file_has_ever_been_committed() -> None:
    """
    History is the part you cannot fix later.

    Removing a committed key from the working tree leaves it in every clone;
    this fails while the mistake is still one `git reset` away.
    """
    result = subprocess.run(
        ["git", "log", "--all", "--format=%H", "--name-only", "--", ".env", "*.pem", "*.key"],
        cwd=PROJECT_ROOT,
        capture_output=True,
        text=True,
    )

    assert not result.stdout.strip(), (
        f"A secret-bearing file appears in git history:\n{result.stdout[:500]}"
    )
