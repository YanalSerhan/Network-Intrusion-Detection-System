"""
Configuration error reporting.

Data Setup:  No state.
Data Input:  Pydantic validation errors and JSON parse failures.
Data Output: A single exception carrying every problem, formatted for a human.

Why fail fast, and why all at once
----------------------------------
A sensor running on silently-wrong thresholds is worse than one that refuses to
start: it looks healthy while detecting at the wrong sensitivity, and nobody
finds out until an incident is missed. So invalid configuration aborts startup.

Errors are collected rather than raised one at a time. Pydantic's default
message is accurate but reads like a stack trace, and fixing configuration one
restart per mistake is a miserable loop — an operator should see every problem
in one pass and fix them together.
"""

import json
from pathlib import Path
from typing import Any

from pydantic import ValidationError


class ConfigurationError(Exception):
    """Raised when configuration cannot be loaded or does not validate."""

    def __init__(self, message: str, problems: list[str] | None = None) -> None:
        """
        Initialise the error.

        Args:
            message:  Summary line.
            problems: Individual problems, one per line in the report.
        """
        self.problems = problems or []
        super().__init__(self._format(message, self.problems))

    @staticmethod
    def _format(message: str, problems: list[str]) -> str:
        """Render the summary and problems as an operator-readable block."""
        if not problems:
            return message
        listed = "\n".join(f"  - {problem}" for problem in problems)
        return f"{message}\n{listed}"


def describe_validation_error(source: str, error: ValidationError) -> list[str]:
    """
    Turn a Pydantic error into one readable line per problem.

    Args:
        source: File the configuration came from, named so an operator knows
            which file to open.
        error:  The validation error.

    Returns:
        One string per problem, naming the field path and the reason.
    """
    problems: list[str] = []
    for detail in error.errors():
        location = ".".join(str(part) for part in detail.get("loc", ())) or "(root)"
        reason = detail.get("msg", "is invalid")
        given = detail.get("input")

        line = f"{source}: '{location}' {reason}"
        # Echoing the offending value turns "greater than 0 required" into
        # something an operator can act on without opening the file.
        if given is not None and not isinstance(given, (dict, list)):
            line += f" (got: {given!r})"
        problems.append(line)

    return problems


def load_json_file(path: Path) -> dict[str, Any]:
    """
    Read a JSON config file, failing with a clear message.

    A missing file is not an error — every section has defaults, so a partial
    or absent config is a valid way to run. Malformed JSON is an error, because
    it means the operator intended settings that are not being applied.

    Args:
        path: File to read.

    Returns:
        The parsed object, or an empty dict when the file does not exist.

    Raises:
        ConfigurationError: If the file is unreadable or not a JSON object.
    """
    if not path.exists():
        return {}

    try:
        with path.open(encoding="utf-8") as handle:
            parsed = json.load(handle)
    except json.JSONDecodeError as exc:
        raise ConfigurationError(
            f"Could not parse {path.name}.",
            [f"{path}: invalid JSON at line {exc.lineno}, column {exc.colno} ({exc.msg})"],
        ) from exc
    except OSError as exc:
        raise ConfigurationError(
            f"Could not read {path.name}.", [f"{path}: {exc.strerror or exc}"]
        ) from exc

    if not isinstance(parsed, dict):
        raise ConfigurationError(
            f"Could not use {path.name}.",
            [f"{path}: expected a JSON object, found {type(parsed).__name__}"],
        )

    return parsed
